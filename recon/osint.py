#!/usr/bin/env python3
"""
osint.py — пассивная OSINT разведка по домену / компании
Standoff 365 Toolkit

Использование:
  python osint.py -d target.com
  python osint.py -d target.com -c "Company Name"
  python osint.py -d target.com --out ~/loot/company
"""

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("[!] pip install requests")

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
        console.print(f"\n[bold magenta]{'═'*52}[/bold magenta]")
        console.print(f"[bold magenta]  {title}[/bold magenta]")
        console.print(f"[bold magenta]{'═'*52}[/bold magenta]\n")
    else:
        print(f"\n{'='*52}\n  {title}\n{'='*52}\n")

def save(data, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, (list, dict)):
        with open(path, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    else:
        with open(path, "w") as f:
            f.write(str(data))

def save_lines(lines, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(str(l) for l in lines) + "\n")

def run_cmd(cmd, timeout=30, silent=False):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception as e:
        if not silent:
            log(f"Ошибка: {e}", "warn")
        return ""

def http_get(url, headers=None, timeout=15, params=None):
    if not HAS_REQUESTS:
        return None
    try:
        resp = requests.get(
            url,
            headers=headers or {"User-Agent": "Mozilla/5.0"},
            timeout=timeout,
            params=params,
            verify=False
        )
        return resp
    except Exception:
        return None

def check_cmd(name):
    import shutil
    return shutil.which(name) is not None


# =============================================================================
# 1. WHOIS / RDAP
# =============================================================================

def whois_lookup(domain, out_dir):
    section("WHOIS / RDAP")
    whois_dir = out_dir / "whois"
    whois_dir.mkdir(exist_ok=True)

    results = {}

    # whois через системную утилиту
    log("whois lookup...", "info")
    output = run_cmd(["whois", domain], timeout=15, silent=True)
    if not output:
        log("whois таймаут — пропускаю", "warn")
    if output:
        save(output, whois_dir / "whois.txt")

        interesting_keys = [
            "registrant", "admin", "tech", "email", "phone",
            "organization", "org", "name server", "nameserver",
            "nserver", "created", "updated", "expires",
            "registrar", "status"
        ]
        found = {}
        for line in output.splitlines():
            line_lower = line.lower()
            for key in interesting_keys:
                if key in line_lower and ":" in line:
                    k, _, v = line.partition(":")
                    k = k.strip()
                    v = v.strip()
                    if v and len(v) > 1:
                        found[k] = v

        if found:
            results["whois"] = found
            log("Ключевые данные из WHOIS:", "ok")
            for k, v in list(found.items())[:15]:
                log(f"  {k}: {v}", "info")

    # RDAP — больше структурированных данных
    log("RDAP lookup...", "info")
    rdap_resp = http_get(f"https://rdap.org/domain/{domain}")
    if rdap_resp and rdap_resp.status_code == 200:
        try:
            rdap_data = rdap_resp.json()
            save(rdap_data, whois_dir / "rdap.json")

            emails = []
            for entity in rdap_data.get("entities", []):
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "email" and len(item) > 3:
                            emails.append(item[3])

            if emails:
                results["rdap_emails"] = emails
                log(f"RDAP emails: {emails}", "ok")

        except Exception:
            pass

    return results


# =============================================================================
# 2. DNS РАЗВЕДКА
# =============================================================================

def dns_recon(domain, out_dir):
    section("DNS Разведка")
    dns_dir = out_dir / "dns"
    dns_dir.mkdir(exist_ok=True)

    results = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]
    all_records = {}

    for rtype in record_types:
        output = run_cmd(["dig", "+short", rtype, domain], timeout=10, silent=True)
        if output:
            records = [l.strip() for l in output.splitlines() if l.strip()]
            all_records[rtype] = records
            log(f"  {rtype}: {', '.join(records[:5])}", "ok")

    save(all_records, dns_dir / "dns_records.json")
    results["dns"] = all_records

    # TXT → SPF, DKIM, DMARC, сервисы
    if "TXT" in all_records:
        interesting_txt = []
        for txt in all_records["TXT"]:
            if any(k in txt.lower() for k in [
                "spf", "dkim", "dmarc", "google", "microsoft",
                "atlassian", "sendgrid", "mailchimp", "verify",
                "aws", "azure", "stripe", "slack"
            ]):
                interesting_txt.append(txt)

        if interesting_txt:
            log("Интересные TXT записи:", "ok")
            for txt in interesting_txt:
                log(f"  {txt[:120]}", "info")
            results["interesting_txt"] = interesting_txt

    # Zone Transfer попытка
    log("Zone Transfer попытка (AXFR)...", "info")
    ns_servers = all_records.get("NS", [])
    for ns in ns_servers[:3]:
        ns = ns.rstrip(".")
        zt_output = run_cmd(["dig", "axfr", f"@{ns}", domain], timeout=15, silent=True)
        if zt_output and "Transfer failed" not in zt_output and len(zt_output) > 100:
            save(zt_output, dns_dir / f"zone_transfer_{ns}.txt")
            log(f"ZONE TRANSFER УСПЕШЕН с {ns}!", "warn")
            results["zone_transfer"] = ns
        else:
            log(f"  AXFR {ns}: отказано (нормально)", "info")

    # Email security анализ
    issues = []
    txt_joined = " ".join(all_records.get("TXT", []))
    if "v=spf1" not in txt_joined:
        issues.append("SPF отсутствует → возможен email spoofing")
        log("  [!] SPF НЕ настроен → email spoofing возможен", "warn")
    else:
        log("  SPF настроен", "ok")

    dmarc_output = run_cmd(["dig", "+short", "TXT", f"_dmarc.{domain}"], timeout=10, silent=True)
    if not dmarc_output:
        issues.append("DMARC отсутствует → возможен email spoofing")
        log("  [!] DMARC НЕ настроен", "warn")
    else:
        log(f"  DMARC: {dmarc_output[:80]}", "ok")
        if "p=none" in dmarc_output:
            issues.append("DMARC p=none → письма не блокируются")
            log("  [!] DMARC p=none — только мониторинг", "warn")

    if issues:
        results["email_security_issues"] = issues

    return results


# =============================================================================
# 3. ASN / IP РАЗВЕДКА
# =============================================================================

def asn_recon(domain, out_dir):
    section("ASN / IP Разведка")
    asn_dir = out_dir / "asn"
    asn_dir.mkdir(exist_ok=True)

    results = {}

    ip_output = run_cmd(["dig", "+short", "A", domain], timeout=10, silent=True)
    ips = [l.strip() for l in ip_output.splitlines() if l.strip()]

    if not ips:
        log("Не удалось получить IP домена", "warn")
        return results

    results["ips"] = ips
    log(f"IP адреса: {', '.join(ips)}", "ok")

    cloud_providers = {
        "cloudflare": "Cloudflare CDN",
        "amazon":     "AWS",
        "google":     "GCP",
        "microsoft":  "Azure",
        "fastly":     "Fastly CDN",
        "akamai":     "Akamai CDN",
    }

    for ip in ips[:3]:
        log(f"ipinfo.io для {ip}...", "info")
        resp = http_get(f"https://ipinfo.io/{ip}/json")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                save(data, asn_dir / f"ipinfo_{ip}.json")

                org      = data.get("org", "")
                city     = data.get("city", "")
                country  = data.get("country", "")
                hostname = data.get("hostname", "")

                log(f"  {ip} → {org} | {city}, {country}", "ok")
                if hostname:
                    log(f"  Hostname: {hostname}", "info")

                results[ip] = {
                    "org": org, "city": city,
                    "country": country, "hostname": hostname
                }

                for key, name in cloud_providers.items():
                    if key in org.lower():
                        log(f"  → За {name} (может скрывать реальный IP)", "warn")
                        results["cdn"] = name
                        break
            except Exception:
                pass
        time.sleep(0.5)

    # InternetDB (бесплатный Shodan)
    log("InternetDB (Shodan бесплатный)...", "info")
    for ip in ips[:5]:
        resp = http_get(f"https://internetdb.shodan.io/{ip}")
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                save(data, asn_dir / f"internetdb_{ip}.json")

                ports = data.get("ports", [])
                vulns = data.get("vulns", [])
                tags  = data.get("tags", [])
                cpes  = data.get("cpes", [])

                log(f"  {ip}: ports={ports[:10]}", "ok")
                if vulns:
                    log(f"  CVEs: {vulns}", "warn")
                    results.setdefault("vulns", {})[ip] = vulns
                if tags:
                    log(f"  Tags: {tags}", "info")
            except Exception:
                pass
        time.sleep(0.3)

    # Reverse IP lookup
    log("Reverse IP (HackerTarget)...", "info")
    for ip in ips[:2]:
        resp = http_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        if resp and resp.status_code == 200 and "error" not in resp.text.lower():
            hosted = [l.strip() for l in resp.text.splitlines() if l.strip()]
            if hosted:
                log(f"  {ip} → {len(hosted)} хостов на том же IP", "ok")
                for h in hosted[:10]:
                    log(f"    {h}", "info")
                save_lines(hosted, asn_dir / f"reverse_ip_{ip}.txt")
                results[f"hosted_on_{ip}"] = hosted

    return results


# =============================================================================
# 4. EMAIL / СОТРУДНИКИ
# =============================================================================

def find_emails(domain, company, out_dir):
    section("Email / Сотрудники")
    email_dir = out_dir / "emails"
    email_dir.mkdir(exist_ok=True)

    found_emails = set()

    # crt.sh — emails в сертификатах
    log("Поиск emails в Certificate Transparency...", "info")
    resp = http_get(f"https://crt.sh/?q={domain}&output=json")
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            for entry in data:
                for field in ["issuer_name", "name_value"]:
                    val = entry.get(field, "")
                    emails = re.findall(
                        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', val
                    )
                    found_emails.update(emails)
        except Exception:
            pass

    # theHarvester если установлен
    if check_cmd("theHarvester"):
        log("theHarvester...", "info")
        output = run_cmd(
            ["theHarvester", "-d", domain,
             "-b", "anubis,crtsh,dnsdumpster,hackertarget", "-l", "200"],
            timeout=120
        )
        if output:
            save(output, email_dir / "theharvester.txt")
            emails = re.findall(
                r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain), output
            )
            found_emails.update(emails)
            log(f"theHarvester: {len(emails)} emails", "ok")

    # phonebook.cz
    log("phonebook.cz...", "info")
    resp = http_get(
        "https://phonebook.cz/",
        params={"q": domain, "type": "email"}
    )
    if resp and resp.status_code == 200:
        emails = re.findall(
            r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain), resp.text
        )
        found_emails.update(emails)
        if emails:
            log(f"phonebook.cz: {len(emails)} emails", "ok")

    if found_emails:
        emails_list = sorted(found_emails)
        save_lines(emails_list, email_dir / "emails.txt")
        log(f"Итого emails: {len(emails_list)}", "ok")
        for e in emails_list[:10]:
            log(f"  {e}", "info")

        patterns = _guess_email_pattern(emails_list, domain)
        if patterns:
            log(f"Паттерны email: {patterns}", "ok")
            save_lines(patterns, email_dir / "email_patterns.txt")

        return {"emails": emails_list, "email_patterns": patterns}

    return {"emails": [], "email_patterns": []}


def _guess_email_pattern(emails, domain):
    patterns = []
    suffix = f"@{domain}"
    name_parts = [e.replace(suffix, "") for e in emails if suffix in e]

    has_dot       = any("." in p for p in name_parts)
    has_underscore = any("_" in p for p in name_parts)

    if has_dot:
        patterns.append("firstname.lastname@" + domain)
        patterns.append("f.lastname@" + domain)
    if has_underscore:
        patterns.append("firstname_lastname@" + domain)
    if not has_dot and not has_underscore:
        patterns.append("flastname@" + domain)

    return patterns


# =============================================================================
# 5. GITHUB / GITLAB РАЗВЕДКА
# =============================================================================

def github_recon(domain, company, out_dir):
    section("GitHub / GitLab Разведка")
    git_dir = out_dir / "github"
    git_dir.mkdir(exist_ok=True)

    results = {"repos": [], "secrets_hints": [], "gitlab_repos": []}
    company_slug = (
        company.lower().replace(" ", "-").replace(".", "-")
        if company else domain.split(".")[0]
    )

    # GitHub org repos
    log(f"GitHub org: {company_slug}...", "info")
    resp = http_get(
        f"https://api.github.com/orgs/{company_slug}/repos",
        headers={"Accept": "application/vnd.github.v3+json"},
        params={"per_page": 50, "type": "public"}
    )
    if resp and resp.status_code == 200:
        try:
            repos = resp.json()
            if isinstance(repos, list):
                results["repos"] = [r.get("full_name") for r in repos]
                log(f"GitHub: {len(repos)} публичных репо", "ok")
                for r in repos[:10]:
                    log(f"  {r.get('full_name')} | {r.get('description','')[:60]}", "info")
                save(repos, git_dir / "github_repos.json")
        except Exception:
            pass
    else:
        log(f"GitHub org {company_slug} не найдена", "warn")

    # GitHub code search — ищем чувствительные данные
    log("GitHub code search (утечки)...", "info")
    searches = [
        f'"{domain}" password',
        f'"{domain}" secret',
        f'"{domain}" api_key',
        f'"{domain}" internal',
    ]

    search_results = []
    for q in searches:
        resp = http_get(
            "https://api.github.com/search/code",
            headers={"Accept": "application/vnd.github.v3+json"},
            params={"q": q, "per_page": 10}
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                items = data.get("items", [])
                if items:
                    log(f"  '{q}': {len(items)} результатов", "warn")
                    for item in items[:5]:
                        url  = item.get("html_url", "")
                        repo = item.get("repository", {}).get("full_name", "")
                        search_results.append({"query": q, "repo": repo, "url": url})
                        results["secrets_hints"].append(url)
            except Exception:
                pass
        time.sleep(1.5)  # rate limit

    if search_results:
        save(search_results, git_dir / "code_search.json")
        log(f"Потенциальные утечки GitHub: {len(search_results)}", "warn")

    # GitLab
    log("GitLab поиск...", "info")
    resp = http_get(
        "https://gitlab.com/api/v4/projects",
        params={"search": domain, "visibility": "public", "per_page": 20}
    )
    if resp and resp.status_code == 200:
        try:
            projects = resp.json()
            if projects:
                log(f"GitLab: {len(projects)} публичных проектов", "ok")
                for p in projects[:5]:
                    log(f"  {p.get('path_with_namespace')}", "info")
                results["gitlab_repos"] = [p.get("web_url") for p in projects]
                save(projects, git_dir / "gitlab_projects.json")
        except Exception:
            pass

    return results


# =============================================================================
# 6. WAYBACK MACHINE
# =============================================================================

def wayback_recon(domain, out_dir):
    section("Wayback Machine / Web Archive")
    wb_dir = out_dir / "wayback"
    wb_dir.mkdir(exist_ok=True)

    results = {}

    log("Wayback CDX API...", "info")
    resp = http_get(
        "http://web.archive.org/cdx/search/cdx",
        params={
            "url":      f"*.{domain}/*",
            "output":   "text",
            "fl":       "original",
            "collapse": "urlkey",
            "limit":    "10000",
            "filter":   "statuscode:200",
        },
        timeout=60
    )

    if resp and resp.status_code == 200:
        urls = [l.strip() for l in resp.text.splitlines() if l.strip()]
        log(f"Wayback: {len(urls)} URLs", "ok")

        if urls:
            save_lines(urls, wb_dir / "all_urls.txt")

            categories = {
                "config":   [".env", "config", ".conf", ".cfg", ".ini", ".yaml", ".yml"],
                "backup":   [".bak", ".backup", ".old", ".orig", "backup", "dump"],
                "admin":    ["admin", "administrator", "manage", "panel", "dashboard"],
                "api":      ["/api/", "/v1/", "/v2/", "/graphql", "swagger", "openapi"],
                "secrets":  ["password", "passwd", "secret", "token", "apikey", "api_key"],
                "database": [".sql", ".db", ".sqlite", "database"],
                "source":   [".git", ".svn", "/.git/"],
                "docs":     [".pdf", ".docx", ".xlsx", ".csv"],
                "login":    ["login", "signin", "auth", "oauth", "sso"],
            }

            categorized = {cat: [] for cat in categories}
            for url in urls:
                url_lower = url.lower()
                for cat, patterns in categories.items():
                    for p in patterns:
                        if p in url_lower:
                            categorized[cat].append(url)
                            break

            for cat, cat_urls in categorized.items():
                if cat_urls:
                    save_lines(cat_urls, wb_dir / f"urls_{cat}.txt")
                    lvl = "warn" if cat in ("admin", "secrets", "source") else "ok"
                    log(f"  {cat}: {len(cat_urls)} URLs", lvl)

            results["urls_total"] = len(urls)
            results["categorized"] = {k: len(v) for k, v in categorized.items() if v}

    # gau если установлен
    if check_cmd("gau"):
        log("gau (getallurls)...", "info")
        output = run_cmd(["gau", "--subs", domain], timeout=120)
        if output:
            gau_urls = [l.strip() for l in output.splitlines() if l.strip()]
            save_lines(gau_urls, wb_dir / "gau_urls.txt")
            log(f"gau: {len(gau_urls)} URLs", "ok")

    # waybackurls если установлен
    if check_cmd("waybackurls"):
        log("waybackurls...", "info")
        output = run_cmd(["waybackurls", domain], timeout=60)
        if output:
            wb_urls = [l.strip() for l in output.splitlines() if l.strip()]
            save_lines(wb_urls, wb_dir / "waybackurls.txt")
            log(f"waybackurls: {len(wb_urls)} URLs", "ok")

    return results


# =============================================================================
# 7. ТЕХНОЛОГИЧЕСКИЙ СТЕК
# =============================================================================

def tech_stack_osint(domain, company, out_dir):
    section("Технологический стек (OSINT)")
    tech_dir = out_dir / "tech_stack"
    tech_dir.mkdir(exist_ok=True)

    results = {}

    # Вакансии HH.ru → технологии
    if company:
        log(f"Вакансии HH.ru для '{company}'...", "info")
        resp = http_get(
            "https://api.hh.ru/vacancies",
            params={"text": company, "per_page": 20, "area": 1},
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                items = data.get("items", [])
                tech_keywords = [
                    "python", "java", "golang", "c#", ".net", "ruby", "php",
                    "react", "angular", "vue", "kubernetes", "docker", "terraform",
                    "aws", "azure", "gcp", "postgresql", "mysql", "mongodb", "redis",
                    "elasticsearch", "kafka", "nginx", "apache", "iis", "tomcat",
                    "active directory", "ldap", "cisco", "fortinet",
                    "1c", "bitrix", "sap", "oracle", "confluence", "jira",
                ]
                tech_mentions = []
                for item in items:
                    snippet = (
                        (item.get("snippet", {}).get("requirement") or "") + " " +
                        (item.get("snippet", {}).get("responsibility") or "")
                    ).lower()
                    for kw in tech_keywords:
                        if kw in snippet and kw not in tech_mentions:
                            tech_mentions.append(kw)

                if tech_mentions:
                    log(f"Технологии из вакансий: {', '.join(tech_mentions)}", "ok")
                    results["hh_tech"] = tech_mentions
                    save_lines(tech_mentions, tech_dir / "hh_technologies.txt")

                save(items, tech_dir / "hh_vacancies.json")
            except Exception:
                pass

    # Публичная API документация
    log("Поиск публичной API документации...", "info")
    api_paths = [
        f"https://{domain}/api-docs",
        f"https://{domain}/swagger.json",
        f"https://{domain}/swagger-ui.html",
        f"https://{domain}/openapi.json",
        f"https://api.{domain}/swagger",
        f"https://api.{domain}/docs",
        f"https://{domain}/v1/api-docs",
    ]

    found_apis = []
    for url in api_paths:
        resp = http_get(url, timeout=8)
        if resp and resp.status_code in (200, 401, 403):
            found_apis.append(f"{resp.status_code} {url}")
            log(f"  {resp.status_code} {url}",
                "ok" if resp.status_code == 200 else "warn")

    if found_apis:
        save_lines(found_apis, tech_dir / "api_docs_found.txt")
        results["api_docs"] = found_apis

    return results


# =============================================================================
# 8. УТЕЧКИ (публичные источники)
# =============================================================================

def check_leaks(domain, emails, out_dir):
    section("Проверка утечек (публичные источники)")
    leaks_dir = out_dir / "leaks"
    leaks_dir.mkdir(exist_ok=True)

    results = {}

    # HaveIBeenPwned — список публичных утечек
    log("HaveIBeenPwned breaches list...", "info")
    resp = http_get("https://haveibeenpwned.com/api/v3/breaches")
    if resp and resp.status_code == 200:
        try:
            breaches = resp.json()
            domain_root = domain.split(".")[0].lower()
            related = [
                b for b in breaches
                if domain_root in b.get("Domain", "").lower() or
                   domain_root in b.get("Name", "").lower()
            ]
            if related:
                log(f"Потенциально связанные утечки: {len(related)}", "warn")
                for b in related:
                    log(f"  {b.get('Name')} ({b.get('BreachDate')}) "
                        f"— {b.get('PwnCount','?')} аккаунтов", "warn")
                save(related, leaks_dir / "hibp_related.json")
                results["hibp"] = related
            else:
                log("HaveIBeenPwned: прямых совпадений не найдено", "info")
        except Exception:
            pass

    # LeakIX
    log("LeakIX.net...", "info")
    resp = http_get(
        "https://leakix.net/api/search",
        headers={"Accept": "application/json"},
        params={"q": f"host:{domain}", "scope": "leak"}
    )
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            if data:
                save(data, leaks_dir / "leakix.json")
                cnt = len(data) if isinstance(data, list) else 1
                log(f"LeakIX: {cnt} результатов", "warn")
                results["leakix"] = cnt
        except Exception:
            pass

    # Сохраняем полезные дорки для ручного использования
    dorks = [
        f'site:pastebin.com "{domain}"',
        f'site:pastebin.com "{domain}" password',
        f'site:trello.com "{domain}"',
        f'site:docs.google.com "{domain}"',
        f'"{domain}" "password" filetype:txt',
        f'"{domain}" site:github.com password',
        f'"{domain}" site:gitlab.com password',
        f'intext:"{domain}" intext:"api_key"',
    ]
    save_lines(dorks, leaks_dir / "google_dorks.txt")
    log("Google dorks для ручной проверки сохранены", "ok")
    results["dorks_file"] = str(leaks_dir / "google_dorks.txt")

    return results


# =============================================================================
# 9. ИТОГОВЫЙ ОТЧЁТ
# =============================================================================

def generate_report(domain, company, out_dir, all_results):
    section("Итоговый отчёт")

    report = out_dir / "OSINT_REPORT.md"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    whois_r  = all_results.get("whois", {})
    dns_r    = all_results.get("dns", {})
    asn_r    = all_results.get("asn", {})
    emails_r = all_results.get("emails", {})
    github_r = all_results.get("github", {})
    wayback_r = all_results.get("wayback", {})
    tech_r   = all_results.get("tech", {})
    leaks_r  = all_results.get("leaks", {})

    # Критичные находки
    critical = []
    if dns_r.get("zone_transfer"):
        critical.append(f"ZONE TRANSFER возможен через {dns_r['zone_transfer']}")
    for issue in dns_r.get("email_security_issues", []):
        critical.append(issue)
    for ip, cves in asn_r.get("vulns", {}).items():
        critical.append(f"CVEs на {ip}: {', '.join(cves)}")
    if github_r.get("secrets_hints"):
        critical.append(f"Потенциальные утечки на GitHub: {len(github_r['secrets_hints'])} файлов")
    if leaks_r.get("hibp"):
        critical.append(f"Утечки в HaveIBeenPwned: {len(leaks_r['hibp'])}")

    lines = [
        f"# OSINT Report: {domain}",
        f"**Компания:** {company or 'N/A'}",
        f"**Дата:** {ts}",
        "", "---", "",
        "## TL;DR — Критичные находки", "",
    ]

    if critical:
        for c in critical:
            lines.append(f"- ⚠️ {c}")
    else:
        lines.append("- Критичных находок не обнаружено")
    lines.append("")

    # DNS
    lines += ["## DNS / Инфраструктура", ""]
    for rtype, records in dns_r.get("dns", {}).items():
        lines.append(f"**{rtype}:** {', '.join(records[:5])}")
    lines.append("")

    # IP / ASN
    lines += ["## IP / ASN", ""]
    lines.append(f"**IP:** {', '.join(asn_r.get('ips', []))}")
    for ip in asn_r.get("ips", []):
        info = asn_r.get(ip, {})
        if info:
            lines.append(
                f"- {ip}: {info.get('org','')} | "
                f"{info.get('city','')}, {info.get('country','')}"
            )
    if asn_r.get("cdn"):
        lines.append(f"\n> За CDN: **{asn_r['cdn']}** — реальный IP может отличаться")
    lines.append("")

    # Emails
    emails = emails_r.get("emails", [])
    lines += [
        "## Email / Сотрудники", "",
        f"**Найдено:** {len(emails)}",
    ]
    for e in emails[:20]:
        lines.append(f"- {e}")
    patterns = emails_r.get("email_patterns", [])
    if patterns:
        lines.append(f"\n**Паттерны:** {', '.join(patterns)}")
    lines.append("")

    # GitHub
    lines += ["## GitHub / GitLab", ""]
    if github_r.get("repos"):
        lines.append(f"**Публичных репо:** {len(github_r['repos'])}")
        for r in github_r["repos"][:10]:
            lines.append(f"- {r}")
    if github_r.get("secrets_hints"):
        lines.append(f"\n**⚠️ Потенциальные утечки:** {len(github_r['secrets_hints'])}")
        for url in github_r["secrets_hints"][:10]:
            lines.append(f"- {url}")
    lines.append("")

    # Wayback
    lines += ["## Wayback Machine", ""]
    if wayback_r.get("urls_total"):
        lines.append(f"**Всего URLs:** {wayback_r['urls_total']}")
        for cat, cnt in wayback_r.get("categorized", {}).items():
            lines.append(f"- {cat}: {cnt}")
    lines.append("")

    # Tech stack
    hh_tech = tech_r.get("hh_tech", [])
    if hh_tech:
        lines += ["## Технологический стек (из вакансий)", ""]
        lines.append(", ".join(hh_tech))
        lines.append("")

    # Дорки
    lines += [
        "---",
        "## Google Dorks для ручной проверки", "",
        "```",
        f'site:{domain} filetype:pdf',
        f'site:{domain} inurl:admin',
        f'site:{domain} ext:sql | ext:dbf | ext:mdb',
        f'"{domain}" "password" OR "secret"',
        f'"{domain}" site:pastebin.com',
        f'org:"{company or domain}" site:github.com password',
        "```", "",
        "---",
        f"*Отчёт сгенерирован: {ts}*"
    ]

    report.write_text("\n".join(lines))
    log(f"OSINT отчёт: {report}", "ok")

    # Сводная таблица
    if HAS_RICH:
        table = Table(title="OSINT Summary", header_style="bold cyan")
        table.add_column("Модуль", style="cyan")
        table.add_column("Результат", style="bold green")

        table.add_row("Домен", domain)
        table.add_row("IP адреса", ", ".join(asn_r.get("ips", [])))
        table.add_row("Emails", str(len(emails)))
        table.add_row("GitHub репо", str(len(github_r.get("repos", []))))
        table.add_row("Wayback URLs", str(wayback_r.get("urls_total", 0)))
        table.add_row("HIBP утечки", str(len(leaks_r.get("hibp", []))))
        table.add_row("Критичных находок", str(len(critical)))

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
        description="osint.py — пассивная OSINT разведка",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python osint.py -d company.ru
  python osint.py -d company.ru -c "Название Компании"
  python osint.py -d company.ru --skip-wayback
  python osint.py -d company.ru --out ~/loot/target
        """
    )
    p.add_argument("-d", "--domain",  required=True, help="Целевой домен")
    p.add_argument("-c", "--company", default="",    help="Название компании")
    p.add_argument("--out",           help="Директория для результатов")
    p.add_argument("--skip-whois",    action="store_true")
    p.add_argument("--skip-dns",      action="store_true")
    p.add_argument("--skip-asn",      action="store_true")
    p.add_argument("--skip-emails",   action="store_true")
    p.add_argument("--skip-github",   action="store_true")
    p.add_argument("--skip-wayback",  action="store_true")
    p.add_argument("--skip-tech",     action="store_true")
    p.add_argument("--skip-leaks",    action="store_true")
    return p.parse_args()


def main():
    args   = parse_args()
    domain = args.domain.strip()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
            break
    domain = domain.rstrip("/")
    company = args.company.strip()

    if args.out:
        out_dir = Path(args.out)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = Path.home() / "standoff-toolkit" / "loot" / f"osint_{domain}_{ts}"

    out_dir.mkdir(parents=True, exist_ok=True)

    if HAS_RICH:
        console.print(Panel.fit(
            f"[bold cyan]osint.py[/bold cyan]\n"
            f"[green]Домен:[/green]    {domain}\n"
            f"[green]Компания:[/green] {company or '(не указана)'}\n"
            f"[green]Output:[/green]   {out_dir}",
            title="Standoff 365 Toolkit — OSINT",
            border_style="cyan"
        ))

    all_results = {}

    if not args.skip_whois:
        all_results["whois"] = whois_lookup(domain, out_dir)

    if not args.skip_dns:
        all_results["dns"] = dns_recon(domain, out_dir)

    if not args.skip_asn:
        all_results["asn"] = asn_recon(domain, out_dir)

    if not args.skip_emails:
        all_results["emails"] = find_emails(domain, company, out_dir)

    if not args.skip_github:
        all_results["github"] = github_recon(domain, company, out_dir)

    if not args.skip_wayback:
        all_results["wayback"] = wayback_recon(domain, out_dir)

    if not args.skip_tech:
        all_results["tech"] = tech_stack_osint(domain, company, out_dir)

    if not args.skip_leaks:
        emails = all_results.get("emails", {}).get("emails", [])
        all_results["leaks"] = check_leaks(domain, emails, out_dir)

    generate_report(domain, company, out_dir, all_results)

    # Полный JSON
    save(
        {k: v for k, v in all_results.items() if isinstance(v, (dict, list, str, int))},
        out_dir / "osint_full.json"
    )

    log(f"Все результаты: {out_dir}", "ok")


if __name__ == "__main__":
    main()