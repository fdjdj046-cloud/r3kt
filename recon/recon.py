#!/usr/bin/env python3
"""
recon.py — автоматизация внешней разведки
Standoff 365 Toolkit

Использование:
  python recon.py -d target.com
  python recon.py -d target.com --out ~/loot/company
  python recon.py -d target.com --fast          # только subdomains + ports
  python recon.py -d target.com --full          # всё включая nuclei
"""

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# pip install rich
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.table import Table
    from rich import print as rprint
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None


# =============================================================================
# Утилиты вывода
# =============================================================================

def log(msg, level="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    icons = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]", "section": "[>]"}
    colors = {"info": "cyan", "ok": "green", "warn": "yellow", "err": "red", "section": "magenta"}
    icon = icons.get(level, "[*]")
    if HAS_RICH:
        color = colors.get(level, "white")
        console.print(f"[dim]{ts}[/dim] [{color}]{icon}[/{color}] {msg}")
    else:
        print(f"{ts} {icon} {msg}")

def section(title):
    if HAS_RICH:
        console.print(f"\n[bold magenta]{'═'*50}[/bold magenta]")
        console.print(f"[bold magenta]  {title}[/bold magenta]")
        console.print(f"[bold magenta]{'═'*50}[/bold magenta]\n")
    else:
        print(f"\n{'='*50}\n  {title}\n{'='*50}\n")

def check_tool(name):
    return shutil.which(name) is not None

def require_tool(name):
    if not check_tool(name):
        log(f"Инструмент не найден: {name}. Запусти setup.sh", "err")
        return False
    return True


# =============================================================================
# Запуск команд
# =============================================================================

def run(cmd, output_file=None, timeout=300, silent=False):
    """Запускает команду, пишет вывод в файл и возвращает список строк."""
    if not silent:
        log(f"Команда: {' '.join(cmd) if isinstance(cmd, list) else cmd}", "info")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=isinstance(cmd, str)
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]

        if output_file and lines:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w") as f:
                f.write("\n".join(lines) + "\n")

        return lines

    except subprocess.TimeoutExpired:
        log(f"Таймаут ({timeout}s): {cmd}", "warn")
        return []
    except FileNotFoundError:
        log(f"Не найден бинарник: {cmd[0]}", "err")
        return []
    except Exception as e:
        log(f"Ошибка запуска: {e}", "err")
        return []


def run_tee(cmd, output_file, timeout=600):
    """Запускает команду и дублирует вывод в файл в реальном времени."""
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(output_file, "w") as f:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            for line in proc.stdout:
                f.write(line)
            proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        log(f"Таймаут: {cmd[0]}", "warn")
    except Exception as e:
        log(f"Ошибка: {e}", "err")


# =============================================================================
# 1. SUBDOMAIN ENUMERATION
# =============================================================================

def enum_subdomains(domain, out_dir, passive_only=False):
    section("Subdomain Enumeration")
    sub_dir = out_dir / "subdomains"
    sub_dir.mkdir(exist_ok=True)

    all_subs = set()

    # --- subfinder ---
    if check_tool("subfinder"):
        log("subfinder...", "info")
        lines = run(
            ["subfinder", "-d", domain, "-silent", "-all"],
            output_file=sub_dir / "subfinder.txt",
            timeout=180
        )
        all_subs.update(lines)
        log(f"subfinder: {len(lines)} субдоменов", "ok")

    # --- assetfinder ---
    if check_tool("assetfinder"):
        log("assetfinder...", "info")
        lines = run(
            ["assetfinder", "--subs-only", domain],
            output_file=sub_dir / "assetfinder.txt",
            timeout=120
        )
        all_subs.update(lines)
        log(f"assetfinder: {len(lines)} субдоменов", "ok")

    # --- amass (только passive, быстрее) ---
    if check_tool("amass") and not passive_only:
        log("amass (passive)...", "info")
        lines = run(
            ["amass", "enum", "-passive", "-d", domain, "-silent"],
            output_file=sub_dir / "amass.txt",
            timeout=300
        )
        all_subs.update(lines)
        log(f"amass: {len(lines)} субдоменов", "ok")

    # --- crt.sh через curl ---
    log("crt.sh Certificate Transparency...", "info")
    crt_lines = _crtsh(domain)
    all_subs.update(crt_lines)
    if crt_lines:
        with open(sub_dir / "crtsh.txt", "w") as f:
            f.write("\n".join(crt_lines) + "\n")
        log(f"crt.sh: {len(crt_lines)} субдоменов", "ok")

    # Сохраняем дедуплицированный список
    unique = sorted(all_subs)
    all_file = sub_dir / "all_subdomains.txt"
    with open(all_file, "w") as f:
        f.write("\n".join(unique) + "\n")

    log(f"Итого уникальных субдоменов: {len(unique)}", "ok")
    return unique


def _crtsh(domain):
    """Парсим crt.sh через API."""
    try:
        result = subprocess.run(
            ["curl", "-s", f"https://crt.sh/?q=%.{domain}&output=json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return []
        data = json.loads(result.stdout)
        subs = set()
        for entry in data:
            name = entry.get("name_value", "")
            for n in name.splitlines():
                n = n.strip().lstrip("*.")
                if domain in n:
                    subs.add(n)
        return sorted(subs)
    except Exception:
        return []


# =============================================================================
# 2. LIVE HOST DETECTION
# =============================================================================

def detect_live_hosts(subdomains, out_dir):
    section("Live Host Detection")
    sub_dir = out_dir / "subdomains"

    all_subs_file = sub_dir / "all_subdomains.txt"
    if not all_subs_file.exists() or not subdomains:
        log("Нет субдоменов для проверки", "warn")
        return []

    if not require_tool("httpx"):
        return []

    log(f"httpx по {len(subdomains)} хостам...", "info")

    live_file = sub_dir / "live_hosts.txt"
    detail_file = sub_dir / "live_hosts_detail.txt"

    # httpx с детальным выводом
    run_tee(
        ["httpx",
         "-l", str(all_subs_file),
         "-title", "-status-code", "-tech-detect",
         "-content-length", "-web-server",
         "-follow-redirects",
         "-threads", "50",
         "-timeout", "10",
         "-silent",
         "-o", str(detail_file)],
        output_file=str(out_dir / "logs" / "httpx.log"),
        timeout=300
    )

    # Только живые URL
    run(
        ["httpx", "-l", str(all_subs_file), "-silent",
         "-threads", "50", "-timeout", "10"],
        output_file=str(live_file),
        timeout=300,
        silent=True
    )

    live = []
    if live_file.exists():
        live = [l.strip() for l in live_file.read_text().splitlines() if l.strip()]

    log(f"Живых хостов: {len(live)}", "ok")
    return live


# =============================================================================
# 3. PORT SCANNING
# =============================================================================

def port_scan(target, out_dir, fast=False):
    section("Port Scanning")
    port_dir = out_dir / "ports"
    port_dir.mkdir(exist_ok=True)

    # Определяем цель (IP или домен)
    is_range = "/" in target or target.replace(".", "").isdigit()

    if fast:
        # Только самые важные порты для быстрого результата
        ports = "21,22,23,25,53,80,110,135,139,143,389,443,445,587,636,993,995,1433,3306,3389,5432,5985,5986,6379,8080,8443,8888,9200,27017"
        log(f"Fast режим: топ-28 портов, таймаут 2 мин...", "info")
    else:
        ports = "1-65535"
        log("Полное сканирование всех портов (может занять время)...", "info")

    if not require_tool("nmap"):
        return {}

    # masscan для быстрого обнаружения (если есть и сканируем диапазон)
    if check_tool("masscan") and is_range and not fast:
        log("masscan для быстрого обнаружения открытых портов...", "info")
        masscan_out = port_dir / "masscan.txt"
        run(
            ["sudo", "masscan", target, "-p1-65535",
             "--rate=1000", "--open",
             "-oG", str(masscan_out)],
            timeout=300
        )

    # nmap сканирование
    nmap_out = port_dir / "nmap.txt"

    if fast:
        # Fast режим: только открытые порты без -sV/-sC, жёсткий таймаут
        log("nmap fast (топ порты, без version detection)...", "info")
        nmap_cmd = [
            "nmap",
            "--open",
            "-T4",
            "--max-rtt-timeout", "500ms",
            "--max-retries", "1",
            "--host-timeout", "60s",
            "-p", ports,
            "-oA", str(port_dir / "nmap"),
            target
        ]
        run_tee(nmap_cmd, str(out_dir / "logs" / "nmap.log"), timeout=120)
    else:
        # Normal/Full режим: version detection, все порты
        log("nmap полное сканирование...", "info")
        nmap_cmd = [
            "nmap", "-sV", "-sC",
            "--open", "-T4",
            "-p-", "--min-rate", "1000",
            "-oA", str(port_dir / "nmap"),
            target
        ]
        run_tee(nmap_cmd, str(out_dir / "logs" / "nmap.log"), timeout=600)

    # Парсим результаты
    results = _parse_nmap(nmap_out)
    if results:
        log(f"Открытых портов: {sum(len(v) for v in results.values())}", "ok")
        _print_port_table(results)

    return results


def _parse_nmap(nmap_file):
    """Простой парсер nmap grepable/text output."""
    results = {}
    if not Path(str(nmap_file)).exists():
        # Пробуем .gnmap
        gnmap = str(nmap_file).replace(".txt", ".gnmap")
        if not Path(gnmap).exists():
            return results
        nmap_file = gnmap

    try:
        for line in Path(str(nmap_file)).read_text().splitlines():
            if "open" in line and "Host:" in line:
                parts = line.split()
                host = ""
                for i, p in enumerate(parts):
                    if p == "Host:":
                        host = parts[i+1]
                        break
                if host not in results:
                    results[host] = []
                # Ищем порты
                for p in parts:
                    if "/open/" in p or "/open" in p:
                        results[host].append(p)
    except Exception:
        pass
    return results


def _print_port_table(results):
    if not HAS_RICH or not results:
        return
    table = Table(title="Открытые порты", show_header=True)
    table.add_column("Host", style="cyan")
    table.add_column("Порты", style="green")
    for host, ports in results.items():
        table.add_row(host, ", ".join(ports[:10]) + ("..." if len(ports) > 10 else ""))
    console.print(table)


# =============================================================================
# 4. TECHNOLOGY DETECTION
# =============================================================================

def detect_tech(live_hosts, out_dir):
    section("Technology Detection")
    tech_dir = out_dir / "tech"
    tech_dir.mkdir(exist_ok=True)

    if not live_hosts:
        log("Нет живых хостов для анализа", "warn")
        return {}

    live_file = tech_dir / "targets.txt"
    with open(live_file, "w") as f:
        f.write("\n".join(live_hosts) + "\n")

    # httpx tech-detect (уже запускали, но повторим на живых)
    if check_tool("httpx"):
        log("httpx tech-detect...", "info")
        tech_file = tech_dir / "tech_detect.txt"
        run_tee(
            ["httpx", "-l", str(live_file),
             "-tech-detect", "-title", "-status-code",
             "-web-server", "-silent",
             "-o", str(tech_file)],
            str(out_dir / "logs" / "tech.log"),
            timeout=300
        )

        # Парсим и выводим интересное
        if tech_file.exists():
            interesting = []
            for line in tech_file.read_text().splitlines():
                # Ищем интересные технологии
                keywords = ["wordpress", "joomla", "drupal", "jenkins",
                           "gitlab", "grafana", "kibana", "elastic",
                           "spring", "struts", "apache", "nginx",
                           "iis", "php", "asp.net", "tomcat",
                           "confluence", "jira", "sonarqube"]
                line_lower = line.lower()
                for kw in keywords:
                    if kw in line_lower:
                        interesting.append(line)
                        break

            if interesting:
                log(f"Интересные технологии ({len(interesting)} хостов):", "ok")
                for item in interesting[:20]:
                    log(f"  {item}", "info")

                with open(tech_dir / "interesting.txt", "w") as f:
                    f.write("\n".join(interesting) + "\n")

    # whatweb если есть
    if check_tool("whatweb") and len(live_hosts) <= 20:
        log("whatweb...", "info")
        for host in live_hosts[:20]:
            run(
                ["whatweb", "-a", "3", host],
                output_file=tech_dir / f"whatweb_{host.replace('://', '_').replace('/', '_')}.txt",
                timeout=30,
                silent=True
            )

    log("Tech detection завершён", "ok")


# =============================================================================
# 5. DIRECTORY / VHOST FUZZING
# =============================================================================

def dir_fuzz(live_hosts, out_dir):
    section("Directory Fuzzing")
    fuzz_dir = out_dir / "fuzzing"
    fuzz_dir.mkdir(exist_ok=True)

    if not require_tool("ffuf"):
        return
    if not live_hosts:
        log("Нет хостов для фаззинга", "warn")
        return

    # Путь к wordlist
    toolkit = Path.home() / "standoff-toolkit" / "wordlists"
    wordlists_candidates = [
        toolkit / "SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        toolkit / "SecLists/Discovery/Web-Content/common.txt",
        Path("/usr/share/wordlists/dirb/common.txt"),
        Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
    ]

    wordlist = None
    for wl in wordlists_candidates:
        if wl.exists():
            wordlist = wl
            break

    if not wordlist:
        log("Wordlist не найден. Запусти setup.sh для установки SecLists", "warn")
        return

    # Берём первые 10 живых хостов для фаззинга
    targets = live_hosts[:10]
    log(f"ffuf по {len(targets)} хостам...", "info")

    for host in targets:
        safe_name = host.replace("://", "_").replace("/", "_").replace(":", "_")
        out_file = fuzz_dir / f"{safe_name}.json"

        log(f"  → {host}", "info")
        run(
            ["ffuf",
             "-u", f"{host}/FUZZ",
             "-w", str(wordlist),
             "-mc", "200,201,204,301,302,307,401,403,405",
             "-t", "50",
             "-timeout", "10",
             "-o", str(out_file),
             "-of", "json",
             "-s"],  # silent
            timeout=180,
            silent=True
        )

    # Парсим результаты — ищем интересное
    found = []
    for jf in fuzz_dir.glob("*.json"):
        try:
            data = json.loads(jf.read_text())
            for r in data.get("results", []):
                status = r.get("status", 0)
                url = r.get("url", "")
                length = r.get("length", 0)
                if status in (200, 201) or (status in (301, 302) and length > 0):
                    found.append(f"{status} {url} (length:{length})")
        except Exception:
            pass

    if found:
        log(f"Найдено {len(found)} интересных путей:", "ok")
        for item in found[:30]:
            log(f"  {item}", "ok")
        with open(fuzz_dir / "interesting_paths.txt", "w") as f:
            f.write("\n".join(found) + "\n")
    else:
        log("Ничего интересного не найдено", "warn")


# =============================================================================
# 6. NUCLEI SCANNING
# =============================================================================

def nuclei_scan(live_hosts, out_dir, severity="critical,high,medium"):
    section("Nuclei Vulnerability Scan")
    nuclei_dir = out_dir / "nuclei"
    nuclei_dir.mkdir(exist_ok=True)

    if not require_tool("nuclei"):
        return []
    if not live_hosts:
        log("Нет хостов для nuclei", "warn")
        return []

    live_file = nuclei_dir / "targets.txt"
    with open(live_file, "w") as f:
        f.write("\n".join(live_hosts) + "\n")

    findings = []

    # Запускаем несколько шаблонов по категориям
    scan_configs = [
        {
            "name": "CVEs",
            "tags": "cve",
            "output": nuclei_dir / "cves.txt",
        },
        {
            "name": "Exposures (панели, логи, конфиги)",
            "tags": "exposure,config,log",
            "output": nuclei_dir / "exposures.txt",
        },
        {
            "name": "Misconfigurations",
            "tags": "misconfig",
            "output": nuclei_dir / "misconfig.txt",
        },
        {
            "name": "Default Credentials",
            "tags": "default-login",
            "output": nuclei_dir / "default_creds.txt",
        },
        {
            "name": "Takeover",
            "tags": "takeover",
            "output": nuclei_dir / "takeover.txt",
        },
    ]

    for cfg in scan_configs:
        log(f"nuclei: {cfg['name']}...", "info")
        cmd = [
            "nuclei",
            "-l", str(live_file),
            "-tags", cfg["tags"],
            "-severity", severity,
            "-o", str(cfg["output"]),
            "-silent",
            "-c", "25",
            "-timeout", "10",
            "-retries", "2",
            "-no-color",
        ]
        run_tee(cmd, str(out_dir / "logs" / f"nuclei_{cfg['tags']}.log"), timeout=600)

        if cfg["output"].exists():
            lines = [l for l in cfg["output"].read_text().splitlines() if l.strip()]
            if lines:
                findings.extend(lines)
                log(f"  → {len(lines)} находок в {cfg['name']}", "ok")

    # Сводный файл
    if findings:
        all_findings = nuclei_dir / "all_findings.txt"
        with open(all_findings, "w") as f:
            f.write("\n".join(sorted(set(findings))) + "\n")
        log(f"Nuclei итого: {len(findings)} находок → {all_findings}", "ok")
    else:
        log("Nuclei: находок не обнаружено", "warn")

    return findings


# =============================================================================
# 7. SCREENSHOTS
# =============================================================================

def take_screenshots(live_hosts, out_dir):
    section("Screenshots")
    shots_dir = out_dir / "screenshots"
    shots_dir.mkdir(exist_ok=True)

    if not check_tool("gowitness") and not check_tool("aquatone"):
        log("gowitness/aquatone не найдены, пропускаю скриншоты", "warn")
        log("  go install github.com/sensepost/gowitness@latest", "info")
        return

    if not live_hosts:
        return

    live_file = shots_dir / "targets.txt"
    with open(live_file, "w") as f:
        f.write("\n".join(live_hosts) + "\n")

    if check_tool("gowitness"):
        log("gowitness скриншоты...", "info")
        run_tee(
            ["gowitness", "file",
             "-f", str(live_file),
             "--screenshot-path", str(shots_dir),
             "--threads", "10"],
            str(out_dir / "logs" / "gowitness.log"),
            timeout=300
        )
        log(f"Скриншоты в {shots_dir}", "ok")


# =============================================================================
# 8. ИТОГОВЫЙ ОТЧЁТ
# =============================================================================

def generate_report(domain, out_dir, results):
    section("Генерация отчёта")

    report_file = out_dir / "REPORT.md"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        f"# Recon Report: {domain}",
        f"**Дата:** {ts}",
        f"**Директория:** {out_dir}",
        "",
        "---",
        "",
    ]

    # Субдомены
    sub_count = len(results.get("subdomains", []))
    live_count = len(results.get("live_hosts", []))
    lines += [
        "## Субдомены",
        f"- Найдено: **{sub_count}**",
        f"- Живых: **{live_count}**",
        "",
    ]

    if results.get("live_hosts"):
        lines.append("### Живые хосты")
        for h in results["live_hosts"][:50]:
            lines.append(f"- {h}")
        if live_count > 50:
            lines.append(f"- ... и ещё {live_count - 50}")
        lines.append("")

    # Nuclei
    nuclei_findings = results.get("nuclei", [])
    if nuclei_findings:
        lines += [
            "## Nuclei Findings",
            f"Всего: **{len(nuclei_findings)}**",
            "",
            "```",
        ]
        lines.extend(nuclei_findings[:50])
        lines.append("```")
        lines.append("")

    # Интересные пути
    interesting_file = out_dir / "fuzzing" / "interesting_paths.txt"
    if interesting_file.exists():
        paths = interesting_file.read_text().splitlines()
        lines += [
            "## Интересные пути (Directory Fuzzing)",
            f"Найдено: **{len(paths)}**",
            "",
            "```",
        ]
        lines.extend(paths[:30])
        lines.append("```")
        lines.append("")

    # Структура файлов
    lines += [
        "---",
        "## Структура результатов",
        "```",
    ]
    for f in sorted(out_dir.rglob("*.txt")):
        rel = f.relative_to(out_dir)
        size = f.stat().st_size
        count = len(f.read_text().splitlines())
        lines.append(f"{rel} ({count} строк, {size} байт)")
    lines.append("```")

    report_file.write_text("\n".join(lines))
    log(f"Отчёт сохранён: {report_file}", "ok")

    # Краткий итог в терминал
    if HAS_RICH:
        table = Table(title="Итоги разведки", show_header=True, header_style="bold cyan")
        table.add_column("Параметр", style="cyan")
        table.add_column("Значение", style="bold green")
        table.add_row("Домен", domain)
        table.add_row("Субдоменов", str(sub_count))
        table.add_row("Живых хостов", str(live_count))
        table.add_row("Nuclei findings", str(len(nuclei_findings)))
        table.add_row("Отчёт", str(report_file))
        console.print("\n")
        console.print(table)


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="recon.py — автоматизация внешней разведки",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python recon.py -d company.ru
  python recon.py -d company.ru --fast
  python recon.py -d company.ru --full --out ~/loot/company
  python recon.py -d company.ru --skip-nuclei --skip-fuzz
        """
    )
    parser.add_argument("-d", "--domain", required=True, help="Целевой домен")
    parser.add_argument("--out", help="Директория для результатов (по умолчанию ~/standoff-toolkit/loot/DOMAIN_DATE)")
    parser.add_argument("--fast", action="store_true", help="Быстрый режим (только subs + top ports + tech)")
    parser.add_argument("--full", action="store_true", help="Полный режим (всё, включая скриншоты)")
    parser.add_argument("--skip-subs", action="store_true", help="Пропустить subdomain enum")
    parser.add_argument("--skip-ports", action="store_true", help="Пропустить port scan")
    parser.add_argument("--skip-fuzz", action="store_true", help="Пропустить directory fuzzing")
    parser.add_argument("--skip-nuclei", action="store_true", help="Пропустить nuclei")
    parser.add_argument("--severity", default="critical,high,medium", help="Severity для nuclei (default: critical,high,medium)")
    parser.add_argument("--passive", action="store_true", help="Только пассивная разведка")
    return parser.parse_args()


def main():
    args = parse_args()
    domain = args.domain.strip()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
            break
    domain = domain.rstrip("/")

    # Директория для результатов
    if args.out:
        out_dir = Path(args.out)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = Path.home() / "standoff-toolkit" / "loot" / f"{domain}_{ts}"

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "logs").mkdir(exist_ok=True)

    if HAS_RICH:
        console.print(Panel.fit(
            f"[bold cyan]recon.py[/bold cyan]\n"
            f"[green]Домен:[/green] {domain}\n"
            f"[green]Output:[/green] {out_dir}\n"
            f"[green]Режим:[/green] {'fast' if args.fast else 'full' if args.full else 'normal'}",
            title="Standoff 365 Toolkit",
            border_style="cyan"
        ))
    else:
        print(f"\n[*] Target: {domain}")
        print(f"[*] Output: {out_dir}\n")

    start = time.time()
    results = {"subdomains": [], "live_hosts": [], "nuclei": []}

    # 1. Субдомены
    if not args.skip_subs:
        results["subdomains"] = enum_subdomains(domain, out_dir, passive_only=args.passive)

    # 2. Живые хосты
    results["live_hosts"] = detect_live_hosts(results["subdomains"], out_dir)

    # 3. Порты
    if not args.skip_ports:
        port_scan(domain, out_dir, fast=args.fast)

    # 4. Технологии
    if results["live_hosts"]:
        detect_tech(results["live_hosts"], out_dir)

    # 5. Directory fuzzing
    if not args.skip_fuzz and not args.fast:
        dir_fuzz(results["live_hosts"], out_dir)

    # 6. Nuclei
    if not args.skip_nuclei and not args.fast:
        results["nuclei"] = nuclei_scan(
            results["live_hosts"], out_dir,
            severity=args.severity
        )

    # 7. Screenshots (только в full режиме)
    if args.full:
        take_screenshots(results["live_hosts"], out_dir)

    # 8. Отчёт
    generate_report(domain, out_dir, results)

    elapsed = time.time() - start
    log(f"Готово! Время: {elapsed:.0f}с | Результаты: {out_dir}", "ok")


if __name__ == "__main__":
    main()