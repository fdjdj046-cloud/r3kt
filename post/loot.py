#!/usr/bin/env python3
"""
loot.py — сбор, структурирование и отображение находок
Standoff 365 Toolkit

Помогает организовать найденные данные в процессе пентеста:
- Сохранение кредов, хешей, хостов, заметок
- Поиск по всем находкам
- Генерация итогового отчёта
- Импорт из файлов других инструментов

Использование:
  python loot.py add cred -u admin -p 'Password123' -s smb -H 10.0.0.1
  python loot.py add hash -u krbtgt -H aad3b435:31d6cfe0... -t ntlm
  python loot.py add host -i 10.0.0.1 --hostname DC01 --os 'Windows Server 2019'
  python loot.py add note "BloodHound: DA через ACL цепочку user→server→DC"
  python loot.py show
  python loot.py show creds
  python loot.py search admin
  python loot.py report
  python loot.py import --dir ~/loot/spray_corp_20250101
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None

# =============================================================================
# Конфигурация
# =============================================================================

TOOLKIT_DIR = Path.home() / "standoff-toolkit"
DEFAULT_DB  = TOOLKIT_DIR / "loot" / "loot.json"


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


# =============================================================================
# База данных (простой JSON)
# =============================================================================

class LootDB:
    def __init__(self, db_path: Path):
        self.path = db_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._load()

    def _load(self):
        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except Exception:
                log(f"Ошибка загрузки БД: {self.path}", "warn")
        return {
            "meta": {
                "created":  datetime.now().isoformat(),
                "updated":  datetime.now().isoformat(),
                "version":  "1.0",
            },
            "creds":   [],   # валидные кредентиалы
            "hashes":  [],   # хеши для крека
            "hosts":   [],   # хосты / машины
            "notes":   [],   # заметки
            "flags":   [],   # найденные флаги / артефакты
            "tickets": [],   # Kerberos тикеты
        }

    def save(self):
        self.data["meta"]["updated"] = datetime.now().isoformat()
        self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2))

    # ── CREDS ──────────────────────────────────────────────────────────────

    def add_cred(self, username, password, service="", host="",
                 domain="", port=None, notes="", source="manual"):
        # Проверяем дубликат
        for c in self.data["creds"]:
            if (c["username"] == username and
                c["password"] == password and
                c.get("host") == host):
                log(f"Дубликат: {username}:{password} на {host}", "warn")
                return False

        entry = {
            "id":        self._next_id("creds"),
            "username":  username,
            "password":  password,
            "domain":    domain,
            "service":   service,
            "host":      host,
            "port":      port,
            "notes":     notes,
            "source":    source,
            "ts":        datetime.now().isoformat(),
            "cracked":   False,
        }
        self.data["creds"].append(entry)
        self.save()
        return True

    # ── HASHES ─────────────────────────────────────────────────────────────

    def add_hash(self, username, hash_value, hash_type="ntlm",
                 domain="", host="", cracked_password="", source="manual"):
        for h in self.data["hashes"]:
            if h["hash"] == hash_value and h["username"] == username:
                # Обновляем если взломан
                if cracked_password and not h.get("cracked_password"):
                    h["cracked_password"] = cracked_password
                    h["cracked"] = True
                    self.save()
                    log(f"Обновлён взломанный хеш: {username}:{cracked_password}", "ok")
                else:
                    log(f"Дубликат хеша: {username}", "warn")
                return False

        entry = {
            "id":               self._next_id("hashes"),
            "username":         username,
            "hash":             hash_value,
            "hash_type":        hash_type,
            "domain":           domain,
            "host":             host,
            "cracked":          bool(cracked_password),
            "cracked_password": cracked_password,
            "source":           source,
            "ts":               datetime.now().isoformat(),
        }
        self.data["hashes"].append(entry)
        self.save()
        return True

    # ── HOSTS ──────────────────────────────────────────────────────────────

    def add_host(self, ip, hostname="", os_info="", role="",
                 ports=None, domain="", notes="", source="manual"):
        for h in self.data["hosts"]:
            if h["ip"] == ip:
                # Обновляем существующий
                if hostname: h["hostname"] = hostname
                if os_info:  h["os"]       = os_info
                if role:     h["role"]     = role
                if ports:    h["ports"]    = list(set(h.get("ports", []) + (ports or [])))
                if notes:    h["notes"]   += f"\n{notes}"
                self.save()
                log(f"Хост обновлён: {ip}", "ok")
                return False

        entry = {
            "id":       self._next_id("hosts"),
            "ip":       ip,
            "hostname": hostname,
            "os":       os_info,
            "role":     role,
            "domain":   domain,
            "ports":    ports or [],
            "notes":    notes,
            "source":   source,
            "ts":       datetime.now().isoformat(),
            "owned":    False,
            "tags":     [],
        }
        self.data["hosts"].append(entry)
        self.save()
        return True

    def mark_owned(self, ip_or_hostname):
        for h in self.data["hosts"]:
            if h["ip"] == ip_or_hostname or h.get("hostname") == ip_or_hostname:
                h["owned"] = True
                self.save()
                log(f"Хост помечен как owned: {ip_or_hostname}", "ok")
                return True
        log(f"Хост не найден: {ip_or_hostname}", "warn")
        return False

    # ── NOTES ──────────────────────────────────────────────────────────────

    def add_note(self, text, category="general", host="", source="manual"):
        entry = {
            "id":       self._next_id("notes"),
            "text":     text,
            "category": category,
            "host":     host,
            "source":   source,
            "ts":       datetime.now().isoformat(),
        }
        self.data["notes"].append(entry)
        self.save()
        return True

    # ── FLAGS / АРТЕФАКТЫ ──────────────────────────────────────────────────

    def add_flag(self, value, description="", host="", category="flag"):
        entry = {
            "id":          self._next_id("flags"),
            "value":       value,
            "description": description,
            "host":        host,
            "category":    category,
            "ts":          datetime.now().isoformat(),
        }
        self.data["flags"].append(entry)
        self.save()
        return True

    # ── TICKETS ────────────────────────────────────────────────────────────

    def add_ticket(self, username, ticket_type, ticket_data,
                   domain="", service="", host=""):
        entry = {
            "id":          self._next_id("tickets"),
            "username":    username,
            "ticket_type": ticket_type,   # TGT, TGS, silver, golden
            "ticket_data": ticket_data,   # base64 или путь к файлу
            "domain":      domain,
            "service":     service,
            "host":        host,
            "ts":          datetime.now().isoformat(),
        }
        self.data["tickets"].append(entry)
        self.save()
        return True

    # ── ПОИСК ──────────────────────────────────────────────────────────────

    def search(self, query):
        query_lower = query.lower()
        results = {
            "creds":   [],
            "hashes":  [],
            "hosts":   [],
            "notes":   [],
            "flags":   [],
            "tickets": [],
        }

        for c in self.data["creds"]:
            text = json.dumps(c).lower()
            if query_lower in text:
                results["creds"].append(c)

        for h in self.data["hashes"]:
            text = json.dumps(h).lower()
            if query_lower in text:
                results["hashes"].append(h)

        for h in self.data["hosts"]:
            text = json.dumps(h).lower()
            if query_lower in text:
                results["hosts"].append(h)

        for n in self.data["notes"]:
            if query_lower in n["text"].lower():
                results["notes"].append(n)

        for f in self.data["flags"]:
            text = json.dumps(f).lower()
            if query_lower in text:
                results["flags"].append(f)

        return results

    # ── СТАТИСТИКА ─────────────────────────────────────────────────────────

    def stats(self):
        cracked = sum(1 for h in self.data["hashes"] if h.get("cracked"))
        owned   = sum(1 for h in self.data["hosts"]  if h.get("owned"))
        return {
            "creds":          len(self.data["creds"]),
            "hashes":         len(self.data["hashes"]),
            "hashes_cracked": cracked,
            "hosts":          len(self.data["hosts"]),
            "hosts_owned":    owned,
            "notes":          len(self.data["notes"]),
            "flags":          len(self.data["flags"]),
            "tickets":        len(self.data["tickets"]),
        }

    # ── ВСПОМОГАТЕЛЬНЫЕ ────────────────────────────────────────────────────

    def _next_id(self, collection):
        items = self.data.get(collection, [])
        return max((i.get("id", 0) for i in items), default=0) + 1


# =============================================================================
# Отображение
# =============================================================================

def show_creds(db: LootDB, filter_host=""):
    section("Кредентиалы")
    creds = db.data["creds"]
    if filter_host:
        creds = [c for c in creds if filter_host in c.get("host", "")]

    if not creds:
        log("Кредентиалов не найдено", "warn")
        return

    if HAS_RICH:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("ID",       width=4,  style="dim")
        table.add_column("Username", width=20, style="bold cyan")
        table.add_column("Password", width=20, style="bold green")
        table.add_column("Domain",   width=15)
        table.add_column("Service",  width=10)
        table.add_column("Host",     width=16)
        table.add_column("Notes",    width=20, style="dim")

        for c in creds:
            table.add_row(
                str(c["id"]),
                c.get("username", ""),
                c.get("password", ""),
                c.get("domain",   ""),
                c.get("service",  ""),
                c.get("host",     ""),
                c.get("notes",    "")[:30],
            )
        console.print(table)
    else:
        for c in creds:
            print(f"  [{c['id']}] {c.get('domain','')}\\{c['username']}:{c['password']}"
                  f"  @{c.get('host','')} ({c.get('service','')})")

    log(f"Итого: {len(creds)}", "ok")


def show_hashes(db: LootDB):
    section("Хеши")
    hashes = db.data["hashes"]

    if not hashes:
        log("Хешей не найдено", "warn")
        return

    if HAS_RICH:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("ID",       width=4, style="dim")
        table.add_column("Username", width=20, style="bold cyan")
        table.add_column("Type",     width=10)
        table.add_column("Hash",     width=40, style="dim")
        table.add_column("Cracked",  width=20, style="bold green")
        table.add_column("Host",     width=16)

        for h in hashes:
            cracked = h.get("cracked_password", "")
            cracked_display = f"[green]{cracked}[/green]" if cracked else "[dim]—[/dim]"
            hash_short = h["hash"][:35] + "..." if len(h["hash"]) > 35 else h["hash"]
            table.add_row(
                str(h["id"]),
                h.get("username", ""),
                h.get("hash_type", ""),
                hash_short,
                cracked_display,
                h.get("host", ""),
            )
        console.print(table)
    else:
        for h in hashes:
            status = f"CRACKED:{h['cracked_password']}" if h.get("cracked") else "not cracked"
            print(f"  [{h['id']}] {h['username']}  {h['hash_type']}  {h['hash'][:40]}  [{status}]")

    cracked_count = sum(1 for h in hashes if h.get("cracked"))
    log(f"Итого: {len(hashes)} ({cracked_count} взломано)", "ok")


def show_hosts(db: LootDB):
    section("Хосты")
    hosts = db.data["hosts"]

    if not hosts:
        log("Хостов не найдено", "warn")
        return

    if HAS_RICH:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("ID",       width=4, style="dim")
        table.add_column("IP",       width=16, style="bold cyan")
        table.add_column("Hostname", width=18)
        table.add_column("OS",       width=22)
        table.add_column("Role",     width=10)
        table.add_column("Ports",    width=25, style="dim")
        table.add_column("Owned",    width=6)

        for h in hosts:
            owned_mark = "[bold red]✓ YES[/bold red]" if h.get("owned") else "—"
            ports_str  = ", ".join(str(p) for p in h.get("ports", [])[:8])
            if len(h.get("ports", [])) > 8:
                ports_str += "..."
            table.add_row(
                str(h["id"]),
                h.get("ip",       ""),
                h.get("hostname", ""),
                h.get("os",       "")[:22],
                h.get("role",     ""),
                ports_str,
                owned_mark,
            )
        console.print(table)
    else:
        for h in hosts:
            owned = "[OWNED]" if h.get("owned") else ""
            print(f"  [{h['id']}] {h['ip']}  {h.get('hostname','')}  "
                  f"{h.get('os','')[:20]}  {owned}")

    owned_count = sum(1 for h in hosts if h.get("owned"))
    log(f"Итого: {len(hosts)} хостов ({owned_count} owned)", "ok")


def show_notes(db: LootDB):
    section("Заметки")
    notes = db.data["notes"]

    if not notes:
        log("Заметок нет", "warn")
        return

    for n in notes:
        ts = n["ts"][:16].replace("T", " ")
        cat = n.get("category", "general")
        if HAS_RICH:
            console.print(f"[dim][{n['id']}] {ts} [{cat}][/dim]  {n['text']}")
        else:
            print(f"  [{n['id']}] {ts} [{cat}] {n['text']}")


def show_all(db: LootDB):
    s = db.stats()

    if HAS_RICH:
        table = Table(title="Loot Summary", header_style="bold cyan", show_header=True)
        table.add_column("Категория", style="cyan")
        table.add_column("Всего",     style="bold white", justify="right")
        table.add_column("Детали",    style="green")

        table.add_row("Кредентиалы",   str(s["creds"]),   "")
        table.add_row("Хеши",          str(s["hashes"]),  f"{s['hashes_cracked']} взломано")
        table.add_row("Хосты",         str(s["hosts"]),   f"{s['hosts_owned']} owned")
        table.add_row("Заметки",       str(s["notes"]),   "")
        table.add_row("Флаги/артефакты", str(s["flags"]), "")
        table.add_row("Kerberos тикеты", str(s["tickets"]), "")
        console.print("\n")
        console.print(table)
    else:
        print("\n  === Loot Summary ===")
        for k, v in s.items():
            print(f"  {k}: {v}")

    if db.data["creds"]:
        show_creds(db)
    if db.data["hashes"]:
        show_hashes(db)
    if db.data["hosts"]:
        show_hosts(db)
    if db.data["notes"]:
        show_notes(db)


def show_search_results(results, query):
    section(f"Поиск: '{query}'")
    total = sum(len(v) for v in results.values())

    if total == 0:
        log(f"Ничего не найдено по запросу '{query}'", "warn")
        return

    log(f"Найдено {total} результатов", "ok")

    if results["creds"]:
        log(f"Кредентиалы ({len(results['creds'])}):", "ok")
        for c in results["creds"]:
            print(f"  {c.get('domain','')}\\{c['username']}:{c['password']}"
                  f"  @{c.get('host','')} [{c.get('service','')}]")

    if results["hashes"]:
        log(f"Хеши ({len(results['hashes'])}):", "ok")
        for h in results["hashes"]:
            status = f"→ {h['cracked_password']}" if h.get("cracked") else "(не взломан)"
            print(f"  {h['username']} [{h['hash_type']}] {status}")

    if results["hosts"]:
        log(f"Хосты ({len(results['hosts'])}):", "ok")
        for h in results["hosts"]:
            print(f"  {h['ip']}  {h.get('hostname','')}  {h.get('os','')}")

    if results["notes"]:
        log(f"Заметки ({len(results['notes'])}):", "ok")
        for n in results["notes"]:
            print(f"  {n['text'][:100]}")

    if results["flags"]:
        log(f"Флаги ({len(results['flags'])}):", "ok")
        for f in results["flags"]:
            print(f"  {f['value']}  {f.get('description','')}")


# =============================================================================
# Импорт из файлов других инструментов
# =============================================================================

def import_from_dir(db: LootDB, directory: str):
    section(f"Импорт из директории: {directory}")

    d = Path(directory)
    if not d.exists():
        log(f"Директория не найдена: {directory}", "err")
        return

    imported = {"creds": 0, "hashes": 0, "hosts": 0}

    # Импорт валидных кредов из spray
    for f in d.rglob("valid_creds.txt"):
        log(f"Импорт кредов: {f}", "info")
        for line in f.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            # Формат: domain\user:password
            m = re.match(r'(.+?)\\(.+?):(.+)', line)
            if m:
                domain, user, pwd = m.groups()
                if db.add_cred(user, pwd, domain=domain, source=str(f)):
                    imported["creds"] += 1

    # Импорт хешей из secretsdump/hashdump
    for f in list(d.rglob("*.txt")) + list(d.rglob("*.ntds")):
        if any(kw in f.name.lower() for kw in
               ["secretsdump", "hashdump", "ntds", "sam", "hashes"]):
            log(f"Импорт хешей: {f}", "info")
            for line in f.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Формат secretsdump: domain\username:RID:LM:NT:::
                m = re.match(
                    r'(?:(.+?)\\)?(.+?):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::',
                    line
                )
                if m:
                    domain, user, _, lm, nt = m.groups()
                    hash_val = f"{lm}:{nt}"
                    if db.add_hash(user, hash_val, "ntlm",
                                   domain=domain or "", source=str(f)):
                        imported["hashes"] += 1
                    continue

                # AS-REP / Kerberoast хеши
                if line.startswith("$krb5asrep$") or line.startswith("$krb5tgs$"):
                    hash_type = "asrep" if "asrep" in line else "kerberoast"
                    m2 = re.search(r'\$(?:krb5asrep|krb5tgs)\$\d+\$(.+?)@', line)
                    user2 = m2.group(1) if m2 else "unknown"
                    if db.add_hash(user2, line, hash_type, source=str(f)):
                        imported["hashes"] += 1

    # Импорт хостов из nmap XML
    for f in d.rglob("*.xml"):
        if "nmap" in f.name.lower():
            log(f"Импорт nmap XML: {f}", "info")
            _import_nmap_xml(db, f, imported)

    # Импорт из nuclei findings
    for f in d.rglob("all_findings.txt"):
        log(f"Импорт nuclei findings: {f}", "info")
        for line in f.read_text().splitlines():
            if line.strip():
                db.add_note(line.strip(), category="nuclei", source=str(f))

    # Импорт spray_results.json
    for f in d.rglob("spray_results.json"):
        log(f"Импорт spray результатов: {f}", "info")
        try:
            data = json.loads(f.read_text())
            for cred in data.get("valid_creds", []):
                if db.add_cred(
                    cred.get("user", ""),
                    cred.get("password", ""),
                    domain=data.get("domain", ""),
                    source=str(f)
                ):
                    imported["creds"] += 1
        except Exception:
            pass

    # Импорт bloodhound данных (заметки)
    for f in d.rglob("computers_summary.json"):
        try:
            data = json.loads(f.read_text())
            for comp in data.get("computers", []):
                if "Windows" in comp or "Server" in comp:
                    parts = comp.split()
                    ip = next((p for p in parts if re.match(r'\d+\.\d+', p)), "")
                    if ip:
                        db.add_host(ip, os_info=comp, source=str(f))
                        imported["hosts"] += 1
        except Exception:
            pass

    log(f"Импортировано: {imported['creds']} кредов, "
        f"{imported['hashes']} хешей, {imported['hosts']} хостов", "ok")


def _import_nmap_xml(db: LootDB, xml_file: Path, imported: dict):
    """Парсим nmap XML и импортируем хосты."""
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for host in root.findall("host"):
            # IP
            addr_elem = host.find("address[@addrtype='ipv4']")
            if addr_elem is None:
                continue
            ip = addr_elem.get("addr", "")
            if not ip:
                continue

            # Hostname
            hostname = ""
            hostnames = host.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    hostname = hn.get("name", "")

            # OS
            os_info = ""
            osmatch = host.find(".//osmatch")
            if osmatch is not None:
                os_info = osmatch.get("name", "")

            # Порты
            ports = []
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    ports.append(int(port.get("portid", 0)))

            db.add_host(ip, hostname=hostname, os_info=os_info,
                       ports=ports, source=str(xml_file))
            imported["hosts"] += 1

    except Exception as e:
        log(f"Ошибка парсинга nmap XML: {e}", "warn")


# =============================================================================
# Экспорт hashcat файлов
# =============================================================================

def export_for_hashcat(db: LootDB, out_dir: Path):
    section("Экспорт для hashcat")

    out_dir.mkdir(parents=True, exist_ok=True)
    hashes = db.data["hashes"]

    if not hashes:
        log("Хешей для экспорта нет", "warn")
        return

    # Группируем по типу
    by_type = {}
    for h in hashes:
        if h.get("cracked"):
            continue  # уже взломан
        t = h.get("hash_type", "unknown")
        by_type.setdefault(t, []).append(h["hash"])

    for htype, hash_list in by_type.items():
        fname = out_dir / f"hashcat_{htype}.txt"
        fname.write_text("\n".join(hash_list) + "\n")
        log(f"  {htype}: {len(hash_list)} хешей → {fname}", "ok")

    # hashcat команды
    mode_map = {
        "ntlm":        ("1000",  "hashcat -m 1000  {} rockyou.txt"),
        "netntlmv2":   ("5600",  "hashcat -m 5600  {} rockyou.txt"),
        "asrep":       ("18200", "hashcat -m 18200 {} rockyou.txt"),
        "kerberoast":  ("13100", "hashcat -m 13100 {} rockyou.txt"),
        "wpa2":        ("22000", "hashcat -m 22000 {} rockyou.txt"),
    }

    cmds_file = out_dir / "hashcat_commands.sh"
    with open(cmds_file, "w") as f:
        f.write("#!/bin/bash\n# hashcat команды для взлома\n\n")
        rockyou = Path.home() / "standoff-toolkit/wordlists/rockyou.txt"
        rules   = "/usr/share/hashcat/rules/best64.rule"

        for htype in by_type:
            if htype in mode_map:
                mode, cmd_template = mode_map[htype]
                hash_file = out_dir / f"hashcat_{htype}.txt"
                f.write(f"# {htype.upper()} хеши\n")
                f.write(f"hashcat -m {mode} {hash_file} {rockyou} "
                        f"-r {rules} --status\n\n")

    log(f"hashcat команды → {cmds_file}", "ok")


# =============================================================================
# Генерация отчёта
# =============================================================================

def generate_report(db: LootDB, out_file: Path = None):
    section("Генерация отчёта")

    if out_file is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = TOOLKIT_DIR / "loot" / f"report_{ts}.md"

    s = db.stats()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "# Pentest Loot Report",
        f"**Дата:** {ts}",
        f"**БД:** {db.path}",
        "",
        "---",
        "",
        "## Статистика",
        "",
        f"| Категория | Кол-во |",
        f"|-----------|--------|",
        f"| Кредентиалы | {s['creds']} |",
        f"| Хеши | {s['hashes']} ({s['hashes_cracked']} взломано) |",
        f"| Хосты | {s['hosts']} ({s['hosts_owned']} owned) |",
        f"| Заметки | {s['notes']} |",
        f"| Флаги | {s['flags']} |",
        f"| Kerberos тикеты | {s['tickets']} |",
        "",
        "---",
        "",
    ]

    # Кредентиалы
    if db.data["creds"]:
        lines += [
            "## Кредентиалы", "",
            "| Username | Password | Domain | Service | Host |",
            "|----------|----------|--------|---------|------|",
        ]
        for c in db.data["creds"]:
            lines.append(
                f"| {c['username']} | {c['password']} | "
                f"{c.get('domain','')} | {c.get('service','')} | {c.get('host','')} |"
            )
        lines.append("")

    # Хеши
    if db.data["hashes"]:
        lines += ["## Хеши", "", "| Username | Type | Hash | Cracked |",
                  "|----------|------|------|---------|"]
        for h in db.data["hashes"]:
            cracked = h.get("cracked_password", "—")
            hash_short = h["hash"][:40] + "..." if len(h["hash"]) > 40 else h["hash"]
            lines.append(
                f"| {h['username']} | {h.get('hash_type','')} | "
                f"`{hash_short}` | {cracked} |"
            )
        lines.append("")

    # Owned хосты
    owned = [h for h in db.data["hosts"] if h.get("owned")]
    if owned:
        lines += ["## Owned хосты", ""]
        for h in owned:
            lines.append(f"- **{h['ip']}** ({h.get('hostname','')}) — {h.get('os','')}")
        lines.append("")

    # Все хосты
    if db.data["hosts"]:
        lines += [
            "## Все хосты", "",
            "| IP | Hostname | OS | Role | Ports | Owned |",
            "|----|----------|----|------|-------|-------|",
        ]
        for h in db.data["hosts"]:
            ports_str = ", ".join(str(p) for p in h.get("ports", [])[:8])
            owned_str = "✓" if h.get("owned") else "—"
            lines.append(
                f"| {h['ip']} | {h.get('hostname','')} | {h.get('os','')[:25]} | "
                f"{h.get('role','')} | {ports_str} | {owned_str} |"
            )
        lines.append("")

    # Заметки
    if db.data["notes"]:
        lines += ["## Заметки", ""]
        for n in db.data["notes"]:
            ts_short = n["ts"][:16].replace("T", " ")
            cat = n.get("category", "general")
            lines.append(f"- **[{cat}]** `{ts_short}` {n['text']}")
        lines.append("")

    # Флаги
    if db.data["flags"]:
        lines += ["## Флаги / Артефакты", ""]
        for f in db.data["flags"]:
            lines.append(f"- `{f['value']}` — {f.get('description','')}"
                         f" (хост: {f.get('host','')})")
        lines.append("")

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(lines))
    log(f"Отчёт сохранён: {out_file}", "ok")
    return out_file


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="loot.py — структурированный сбор находок",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Добавить кредентиалы
  python loot.py add cred -u admin -p 'Password123' -s smb -H 10.0.0.1 -d corp.local

  # Добавить хеш (из secretsdump)
  python loot.py add hash -u krbtgt -H 'aad3b435:31d6cfe0...' -t ntlm -d corp.local

  # Добавить хеш как взломанный
  python loot.py add hash -u administrator -H 'aad3b435:8846f7...' -t ntlm --cracked 'Password1'

  # Добавить хост
  python loot.py add host -i 10.0.0.1 --hostname DC01 --os 'Windows Server 2019' -r dc

  # Пометить хост как owned
  python loot.py owned 10.0.0.1

  # Добавить заметку
  python loot.py add note "BloodHound: путь DA через GenericAll на сервер"

  # Добавить Kerberos тикет
  python loot.py add ticket -u administrator -t golden --data 'base64...' -d corp.local

  # Показать всё
  python loot.py show
  python loot.py show creds
  python loot.py show hashes
  python loot.py show hosts

  # Поиск
  python loot.py search admin
  python loot.py search 10.0.0.1

  # Импорт из директории с результатами
  python loot.py import --dir ~/standoff-toolkit/loot/spray_corp_20250101

  # Экспорт для hashcat
  python loot.py hashcat --out ~/hashcat_files

  # Генерация отчёта
  python loot.py report
        """
    )

    p.add_argument("--db", default=str(DEFAULT_DB),
                   help=f"Путь к БД (default: {DEFAULT_DB})")

    sub = p.add_subparsers(dest="command")

    # ── add ──────────────────────────────────────────────────────────────
    add_p = sub.add_parser("add", help="Добавить запись")
    add_sub = add_p.add_subparsers(dest="add_type")

    # add cred
    cred_p = add_sub.add_parser("cred", help="Кредентиалы")
    cred_p.add_argument("-u", "--username", required=True)
    cred_p.add_argument("-p", "--password", required=True)
    cred_p.add_argument("-d", "--domain",   default="")
    cred_p.add_argument("-s", "--service",  default="")
    cred_p.add_argument("-H", "--host",     default="")
    cred_p.add_argument("--port",           type=int, default=None)
    cred_p.add_argument("-n", "--notes",    default="")

    # add hash
    hash_p = add_sub.add_parser("hash", help="Хеш")
    hash_p.add_argument("-u", "--username", required=True)
    hash_p.add_argument("-H", "--hash",     required=True)
    hash_p.add_argument("-t", "--type",     default="ntlm",
                        choices=["ntlm", "netntlmv2", "asrep", "kerberoast", "wpa2", "other"])
    hash_p.add_argument("-d", "--domain",   default="")
    hash_p.add_argument("--host",           default="")
    hash_p.add_argument("--cracked",        default="",
                        help="Взломанный пароль (если уже известен)")

    # add host
    host_p = add_sub.add_parser("host", help="Хост")
    host_p.add_argument("-i", "--ip",       required=True)
    host_p.add_argument("--hostname",       default="")
    host_p.add_argument("--os",             default="")
    host_p.add_argument("-r", "--role",     default="",
                        help="dc, workstation, server, web, ...")
    host_p.add_argument("-d", "--domain",   default="")
    host_p.add_argument("--ports",          nargs="+", type=int, default=[])
    host_p.add_argument("-n", "--notes",    default="")

    # add note
    note_p = add_sub.add_parser("note", help="Заметка")
    note_p.add_argument("text")
    note_p.add_argument("-c", "--category", default="general")
    note_p.add_argument("--host",           default="")

    # add flag
    flag_p = add_sub.add_parser("flag", help="Флаг / артефакт")
    flag_p.add_argument("value")
    flag_p.add_argument("-d", "--description", default="")
    flag_p.add_argument("--host",              default="")
    flag_p.add_argument("-c", "--category",    default="flag")

    # add ticket
    ticket_p = add_sub.add_parser("ticket", help="Kerberos тикет")
    ticket_p.add_argument("-u", "--username", required=True)
    ticket_p.add_argument("-t", "--type",     required=True,
                          choices=["tgt", "tgs", "golden", "silver", "diamond"])
    ticket_p.add_argument("--data",           required=True,
                          help="base64 данные или путь к .kirbi файлу")
    ticket_p.add_argument("-d", "--domain",   default="")
    ticket_p.add_argument("-s", "--service",  default="")
    ticket_p.add_argument("--host",           default="")

    # ── show ─────────────────────────────────────────────────────────────
    show_p = sub.add_parser("show", help="Показать данные")
    show_p.add_argument("what", nargs="?",
                        choices=["all", "creds", "hashes", "hosts", "notes", "flags"],
                        default="all")
    show_p.add_argument("--host", default="", help="Фильтр по хосту")

    # ── search ───────────────────────────────────────────────────────────
    search_p = sub.add_parser("search", help="Поиск по всем данным")
    search_p.add_argument("query")

    # ── owned ─────────────────────────────────────────────────────────────
    owned_p = sub.add_parser("owned", help="Пометить хост как owned")
    owned_p.add_argument("host", help="IP или hostname")

    # ── import ───────────────────────────────────────────────────────────
    import_p = sub.add_parser("import", help="Импорт из директории")
    import_p.add_argument("--dir", required=True, help="Директория с результатами")

    # ── hashcat ──────────────────────────────────────────────────────────
    hc_p = sub.add_parser("hashcat", help="Экспорт для hashcat")
    hc_p.add_argument("--out", default=str(TOOLKIT_DIR / "loot" / "hashcat"))

    # ── report ───────────────────────────────────────────────────────────
    rep_p = sub.add_parser("report", help="Генерация Markdown отчёта")
    rep_p.add_argument("--out", default="", help="Путь к файлу отчёта")

    # ── clear ─────────────────────────────────────────────────────────────
    sub.add_parser("clear", help="Очистить БД (с подтверждением)")

    return p.parse_args()


def main():
    args = parse_args()
    db   = LootDB(Path(args.db))

    if not args.command:
        show_all(db)
        return

    if args.command == "add":
        if args.add_type == "cred":
            ok = db.add_cred(
                args.username, args.password,
                service=args.service, host=args.host,
                domain=args.domain, port=args.port, notes=args.notes
            )
            if ok:
                log(f"Добавлено: {args.domain}\\{args.username}:{args.password}"
                    f" @ {args.host} [{args.service}]", "ok")

        elif args.add_type == "hash":
            ok = db.add_hash(
                args.username, args.hash,
                hash_type=args.type, domain=args.domain,
                host=args.host, cracked_password=args.cracked
            )
            if ok:
                status = f" (взломан: {args.cracked})" if args.cracked else ""
                log(f"Хеш добавлен: {args.username} [{args.type}]{status}", "ok")

        elif args.add_type == "host":
            ok = db.add_host(
                args.ip, hostname=args.hostname,
                os_info=args.os, role=args.role,
                domain=args.domain, ports=args.ports, notes=args.notes
            )
            if ok:
                log(f"Хост добавлен: {args.ip} ({args.hostname}) {args.os}", "ok")

        elif args.add_type == "note":
            db.add_note(args.text, category=args.category, host=args.host)
            log(f"Заметка добавлена: {args.text[:60]}", "ok")

        elif args.add_type == "flag":
            db.add_flag(args.value, description=args.description,
                        host=args.host, category=args.category)
            log(f"Флаг добавлен: {args.value}", "ok")

        elif args.add_type == "ticket":
            db.add_ticket(
                args.username, args.type, args.data,
                domain=args.domain, service=args.service, host=args.host
            )
            log(f"Тикет добавлен: {args.username} [{args.type}]", "ok")

        else:
            log("Укажи тип: cred, hash, host, note, flag, ticket", "err")

    elif args.command == "show":
        what = args.what or "all"
        if what == "creds":
            show_creds(db, filter_host=args.host)
        elif what == "hashes":
            show_hashes(db)
        elif what == "hosts":
            show_hosts(db)
        elif what == "notes":
            show_notes(db)
        else:
            show_all(db)

    elif args.command == "search":
        results = db.search(args.query)
        show_search_results(results, args.query)

    elif args.command == "owned":
        db.mark_owned(args.host)

    elif args.command == "import":
        import_from_dir(db, args.dir)

    elif args.command == "hashcat":
        export_for_hashcat(db, Path(args.out))

    elif args.command == "report":
        out = Path(args.out) if args.out else None
        report_file = generate_report(db, out)
        log(f"Готово: {report_file}", "ok")

    elif args.command == "clear":
        confirm = input("[!] Очистить всю БД? Введи 'yes' для подтверждения: ")
        if confirm.strip().lower() == "yes":
            db.path.unlink(missing_ok=True)
            log("БД очищена", "ok")
        else:
            log("Отменено", "warn")


if __name__ == "__main__":
    main()