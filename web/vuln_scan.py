#!/usr/bin/env python3
"""
vuln_scan.py — сканер типовых веб-уязвимостей
Standoff 365 Toolkit

Проверяет: заголовки безопасности, открытые файлы/директории,
информационные утечки, конфиги, слабые настройки.

Использование:
  python vuln_scan.py -u https://target.com
  python vuln_scan.py -u https://target.com --full
  python vuln_scan.py -u https://target.com --out ~/loot/target
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("[!] pip install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None

TOOLKIT_DIR = Path.home() / "standoff-toolkit"

# =============================================================================
# Утилиты
# =============================================================================

def log(msg, level="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    icons  = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]", "vuln": "[VULN]"}
    colors = {"info": "cyan", "ok": "green", "warn": "yellow", "err": "red", "vuln": "bold red"}
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

def save_json(data, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# =============================================================================
# HTTP клиент
# =============================================================================

class Scanner:
    def __init__(self, base_url, timeout=10, proxy=None,
                 headers=None, cookies=None, verify_ssl=False):
        self.base_url   = normalize_url(base_url)
        self.timeout    = timeout
        self.verify_ssl = verify_ssl
        self.session    = requests.Session()
        self.session.verify  = verify_ssl
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            **(headers or {}),
        })
        if cookies:
            self.session.cookies.update(cookies)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        self.findings = []

    def get(self, path="", full_url=None, allow_redirects=True, timeout=None):
        url = full_url or (self.base_url + "/" + path.lstrip("/"))
        try:
            r = self.session.get(
                url,
                timeout=timeout or self.timeout,
                allow_redirects=allow_redirects,
            )
            return r
        except requests.exceptions.SSLError:
            try:
                r = self.session.get(url, timeout=timeout or self.timeout,
                                     allow_redirects=allow_redirects, verify=False)
                return r
            except Exception:
                return None
        except Exception:
            return None

    def add_finding(self, title, severity, description,
                    url="", evidence="", remediation=""):
        finding = {
            "title":       title,
            "severity":    severity,   # critical, high, medium, low, info
            "description": description,
            "url":         url or self.base_url,
            "evidence":    evidence[:500] if evidence else "",
            "remediation": remediation,
            "ts":          datetime.now().isoformat(),
        }
        self.findings.append(finding)

        sev_colors = {
            "critical": "bold red",
            "high":     "red",
            "medium":   "yellow",
            "low":      "cyan",
            "info":     "dim",
        }
        sev_icons = {
            "critical": "🔴",
            "high":     "🟠",
            "medium":   "🟡",
            "low":      "🔵",
            "info":     "⚪",
        }

        if HAS_RICH:
            c = sev_colors.get(severity, "white")
            icon = sev_icons.get(severity, "•")
            console.print(
                f"  {icon} [{c}][{severity.upper()}][/{c}] "
                f"[bold]{title}[/bold]"
                + (f"\n     [dim]{evidence[:100]}[/dim]" if evidence else "")
            )
        else:
            print(f"  [{severity.upper()}] {title}"
                  + (f": {evidence[:80]}" if evidence else ""))

        return finding


# =============================================================================
# МОДУЛИ ПРОВЕРОК
# =============================================================================

# --- 1. Заголовки безопасности ---

def check_security_headers(scanner: Scanner):
    section("Security Headers")

    r = scanner.get()
    if not r:
        log("Не удалось получить ответ", "err")
        return

    headers = {k.lower(): v for k, v in r.headers.items()}

    checks = [
        {
            "header":      "strict-transport-security",
            "title":       "HSTS отсутствует",
            "severity":    "medium",
            "description": "HTTP Strict Transport Security не настроен.",
            "remediation": "Добавь: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        },
        {
            "header":      "content-security-policy",
            "title":       "CSP отсутствует",
            "severity":    "medium",
            "description": "Content-Security-Policy не настроен — риск XSS.",
            "remediation": "Настрой Content-Security-Policy с ограниченными источниками.",
        },
        {
            "header":      "x-frame-options",
            "title":       "X-Frame-Options отсутствует",
            "severity":    "medium",
            "description": "Страница может быть встроена в iframe — риск Clickjacking.",
            "remediation": "Добавь: X-Frame-Options: DENY или SAMEORIGIN",
        },
        {
            "header":      "x-content-type-options",
            "title":       "X-Content-Type-Options отсутствует",
            "severity":    "low",
            "description": "Браузер может интерпретировать ответы неверно (MIME sniffing).",
            "remediation": "Добавь: X-Content-Type-Options: nosniff",
        },
        {
            "header":      "referrer-policy",
            "title":       "Referrer-Policy отсутствует",
            "severity":    "low",
            "description": "Браузер может передавать Referer третьим сторонам.",
            "remediation": "Добавь: Referrer-Policy: strict-origin-when-cross-origin",
        },
        {
            "header":      "permissions-policy",
            "title":       "Permissions-Policy отсутствует",
            "severity":    "low",
            "description": "Нет ограничений на доступ к API браузера.",
            "remediation": "Добавь Permissions-Policy для ограничения camera/microphone/geolocation.",
        },
    ]

    for check in checks:
        if check["header"] not in headers:
            scanner.add_finding(
                check["title"], check["severity"],
                check["description"],
                remediation=check["remediation"]
            )
        else:
            log(f"  {check['header']}: {headers[check['header']][:80]}", "ok")

    # Проверяем утечку информации в заголовках
    info_headers = ["server", "x-powered-by", "x-aspnet-version",
                    "x-aspnetmvc-version", "x-generator", "x-drupal-cache"]
    for h in info_headers:
        if h in headers:
            scanner.add_finding(
                f"Информационный заголовок: {h}",
                "info",
                f"Заголовок раскрывает технологию: {headers[h]}",
                evidence=f"{h}: {headers[h]}",
                remediation="Скрой или удали информационные заголовки на сервере."
            )

    # CORS проверка
    if "access-control-allow-origin" in headers:
        acao = headers["access-control-allow-origin"]
        if acao == "*":
            scanner.add_finding(
                "CORS: Wildcard Access-Control-Allow-Origin",
                "medium",
                "CORS настроен на * — любой сайт может делать запросы.",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation="Ограничь CORS конкретными доменами."
            )
        else:
            log(f"  CORS: {acao}", "ok")

    # Cookie flags
    set_cookie = r.headers.get("Set-Cookie", "")
    if set_cookie:
        if "httponly" not in set_cookie.lower():
            scanner.add_finding(
                "Cookie без HttpOnly флага",
                "medium",
                "Cookie доступен через JavaScript — риск XSS кражи сессии.",
                evidence=set_cookie[:200],
                remediation="Добавь HttpOnly флаг ко всем session cookies."
            )
        if "secure" not in set_cookie.lower():
            scanner.add_finding(
                "Cookie без Secure флага",
                "low",
                "Cookie передаётся по HTTP.",
                evidence=set_cookie[:200],
                remediation="Добавь Secure флаг ко всем cookies."
            )
        if "samesite" not in set_cookie.lower():
            scanner.add_finding(
                "Cookie без SameSite флага",
                "low",
                "Cookie уязвим к CSRF атакам.",
                evidence=set_cookie[:200],
                remediation="Добавь SameSite=Strict или SameSite=Lax."
            )


# --- 2. Информационные утечки ---

def check_info_disclosure(scanner: Scanner):
    section("Information Disclosure")

    sensitive_paths = [
        # robots/sitemap
        ("robots.txt",       "info",   "robots.txt доступен"),
        ("sitemap.xml",      "info",   "sitemap.xml доступен"),
        # Git/SVN
        (".git/HEAD",        "high",   "Git репозиторий доступен!"),
        (".git/config",      "high",   "Git конфиг доступен!"),
        (".svn/entries",     "high",   "SVN репозиторий доступен!"),
        (".hg/store",        "high",   "Mercurial репозиторий доступен!"),
        # Env/Config
        (".env",             "critical", ".env файл доступен!"),
        (".env.local",       "critical", ".env.local доступен!"),
        (".env.production",  "critical", ".env.production доступен!"),
        (".env.backup",      "critical", ".env.backup доступен!"),
        ("config.php",       "high",   "config.php доступен"),
        ("configuration.php","high",   "configuration.php доступен"),
        ("wp-config.php",    "critical","wp-config.php доступен!"),
        ("config.yml",       "high",   "config.yml доступен"),
        ("config.yaml",      "high",   "config.yaml доступен"),
        ("settings.py",      "high",   "settings.py доступен"),
        ("database.yml",     "high",   "database.yml доступен"),
        ("secrets.yml",      "critical","secrets.yml доступен!"),
        # Логи
        ("error.log",        "high",   "error.log доступен"),
        ("access.log",       "high",   "access.log доступен"),
        ("debug.log",        "medium", "debug.log доступен"),
        ("php_error.log",    "high",   "php_error.log доступен"),
        ("logs/error.log",   "high",   "logs/error.log доступен"),
        # Бэкапы
        ("backup.sql",       "critical","backup.sql доступен!"),
        ("backup.zip",       "critical","backup.zip доступен!"),
        ("dump.sql",         "critical","dump.sql доступен!"),
        ("db.sql",           "critical","db.sql доступен!"),
        ("database.sql",     "critical","database.sql доступен!"),
        ("backup.tar.gz",    "critical","backup.tar.gz доступен!"),
        # phpinfo
        ("phpinfo.php",      "high",   "phpinfo.php доступен"),
        ("info.php",         "high",   "info.php доступен"),
        ("test.php",         "medium", "test.php доступен"),
        # IDE/Editor
        (".DS_Store",        "low",    ".DS_Store доступен"),
        ("Thumbs.db",        "low",    "Thumbs.db доступен"),
        (".idea/workspace.xml", "medium","JetBrains workspace доступен"),
        (".vscode/settings.json","low", "VSCode settings доступен"),
        # Пакетные менеджеры
        ("package.json",     "info",   "package.json доступен"),
        ("composer.json",    "info",   "composer.json доступен"),
        ("Gemfile",          "info",   "Gemfile доступен"),
        ("requirements.txt", "info",   "requirements.txt доступен"),
        ("yarn.lock",        "low",    "yarn.lock доступен"),
        # Docker/K8s
        ("docker-compose.yml","high",  "docker-compose.yml доступен"),
        ("Dockerfile",       "medium", "Dockerfile доступен"),
        (".dockerenv",       "low",    ".dockerenv доступен"),
        # Swagger/API docs
        ("swagger.json",     "medium", "Swagger docs доступен"),
        ("swagger-ui.html",  "medium", "Swagger UI доступен"),
        ("api-docs",         "medium", "API docs доступен"),
        ("openapi.json",     "medium", "OpenAPI spec доступен"),
        ("graphql",          "info",   "GraphQL endpoint"),
        # Прочее
        ("server-status",    "medium", "Apache server-status доступен"),
        ("server-info",      "medium", "Apache server-info доступен"),
        ("actuator",         "high",   "Spring Actuator доступен"),
        ("actuator/env",     "critical","Spring Actuator /env доступен!"),
        ("actuator/health",  "medium", "Spring Actuator /health доступен"),
        ("metrics",          "medium", "Metrics endpoint доступен"),
        ("health",           "info",   "Health endpoint доступен"),
        ("admin",            "medium", "Admin панель доступна"),
        ("console",          "high",   "Консоль доступна"),
        ("phpmyadmin",       "high",   "phpMyAdmin доступен"),
        ("adminer",          "high",   "Adminer доступен"),
        ("jenkins",          "high",   "Jenkins доступен"),
        ("kibana",           "high",   "Kibana доступен"),
        ("grafana",          "medium", "Grafana доступен"),
    ]

    for path, severity, title in sensitive_paths:
        r = scanner.get(path)
        if r and r.status_code in (200, 403, 401):
            url = f"{scanner.base_url}/{path}"

            # Уточняем находку по контенту
            evidence = f"HTTP {r.status_code}"
            if r.status_code == 200:
                # Проверяем что это реально нужный файл
                content = r.text[:500]

                # Git HEAD
                if path == ".git/HEAD" and "ref:" not in content:
                    continue
                # .env — ищем переменные
                if ".env" in path and "=" not in content:
                    continue
                # SQL дамп
                if path.endswith(".sql") and not any(
                    k in content.lower() for k in ["create", "insert", "table", "--"]
                ):
                    continue

                evidence = f"HTTP {r.status_code}, {len(r.content)} байт"
                if len(r.content) > 0:
                    preview = content[:100].replace("\n", " ")
                    evidence += f"\nПревью: {preview}"

            scanner.add_finding(
                title, severity, f"Путь доступен: /{path}",
                url=url, evidence=evidence,
                remediation=f"Закрой доступ к /{path} или удали файл."
            )

        time.sleep(0.05)


# --- 3. Проверка CMS ---

def check_cms(scanner: Scanner):
    section("CMS Detection & Checks")

    r = scanner.get()
    if not r:
        return

    content = r.text.lower()
    headers = {k.lower(): v for k, v in r.headers.items()}
    detected_cms = []

    # WordPress
    if any(x in content for x in ["wp-content", "wp-includes", "wordpress"]):
        detected_cms.append("WordPress")
        log("CMS: WordPress обнаружен", "warn")
        scanner.add_finding(
            "WordPress обнаружен",
            "info",
            "Сайт работает на WordPress.",
            evidence="wp-content/wp-includes в HTML",
        )
        _check_wordpress(scanner)

    # Joomla
    if any(x in content for x in ["/media/jui/", "joomla", "/components/com_"]):
        detected_cms.append("Joomla")
        log("CMS: Joomla обнаружен", "warn")
        _check_joomla(scanner)

    # Drupal
    if any(x in content for x in ["drupal", "/sites/default/", "drupal.org"]):
        detected_cms.append("Drupal")
        log("CMS: Drupal обнаружен", "warn")
        _check_drupal(scanner)

    # Jenkins
    r_jenkins = scanner.get("login")
    if r_jenkins and "jenkins" in r_jenkins.text.lower():
        detected_cms.append("Jenkins")
        log("CMS/App: Jenkins обнаружен", "warn")
        scanner.add_finding(
            "Jenkins панель доступна",
            "high",
            "Jenkins CI/CD панель обнаружена — проверь аутентификацию.",
            url=f"{scanner.base_url}/login",
        )

    # Spring Boot Actuator
    r_actuator = scanner.get("actuator")
    if r_actuator and r_actuator.status_code == 200:
        try:
            data = r_actuator.json()
            if "_links" in data or "status" in data:
                scanner.add_finding(
                    "Spring Boot Actuator открыт",
                    "critical",
                    "Spring Actuator доступен без авторизации — "
                    "утечка конфигурации, env переменных, возможен RCE.",
                    url=f"{scanner.base_url}/actuator",
                    evidence=r_actuator.text[:200],
                    remediation="Закрой /actuator или настрой аутентификацию."
                )
        except Exception:
            pass

    if not detected_cms:
        log("CMS не обнаружен", "info")


def _check_wordpress(scanner: Scanner):
    """Проверки специфичные для WordPress."""
    wp_paths = [
        ("wp-admin/",                  "medium", "WordPress admin доступен"),
        ("wp-login.php",               "info",   "WordPress login страница"),
        ("xmlrpc.php",                 "medium", "WordPress XMLRPC включён"),
        ("wp-json/wp/v2/users",        "high",   "WordPress REST API users — утечка пользователей!"),
        ("wp-config.php.bak",          "critical","wp-config.php.bak доступен!"),
        ("wp-content/debug.log",       "high",   "WordPress debug.log доступен"),
        ("wp-content/uploads/",        "info",   "Uploads директория доступна"),
        ("readme.html",                "info",   "WordPress readme.html — версия раскрыта"),
        ("license.txt",                "info",   "WordPress license.txt доступен"),
    ]
    for path, sev, title in wp_paths:
        r = scanner.get(path)
        if r and r.status_code in (200, 403):
            url = f"{scanner.base_url}/{path}"
            evidence = f"HTTP {r.status_code}"
            # Для users endpoint — ищем реальные данные
            if "users" in path and r.status_code == 200:
                try:
                    users = r.json()
                    if isinstance(users, list) and users:
                        names = [u.get("slug", "") for u in users[:5]]
                        evidence = f"Пользователи: {', '.join(names)}"
                except Exception:
                    pass
            scanner.add_finding(title, sev,
                                 f"WordPress: /{path} доступен",
                                 url=url, evidence=evidence)
        time.sleep(0.05)


def _check_joomla(scanner: Scanner):
    """Проверки для Joomla."""
    paths = [
        ("administrator/",    "medium", "Joomla admin доступен"),
        ("configuration.php", "critical","Joomla configuration.php"),
        ("README.txt",        "info",   "Joomla README — версия"),
    ]
    for path, sev, title in paths:
        r = scanner.get(path)
        if r and r.status_code in (200, 403):
            scanner.add_finding(title, sev,
                                 f"Joomla: /{path}",
                                 url=f"{scanner.base_url}/{path}",
                                 evidence=f"HTTP {r.status_code}")
        time.sleep(0.05)


def _check_drupal(scanner: Scanner):
    """Проверки для Drupal."""
    paths = [
        ("user/login",  "info",   "Drupal login"),
        ("CHANGELOG.txt","info",  "Drupal CHANGELOG — версия"),
        ("sites/default/settings.php", "critical", "Drupal settings.php доступен"),
    ]
    for path, sev, title in paths:
        r = scanner.get(path)
        if r and r.status_code in (200, 403):
            scanner.add_finding(title, sev,
                                 f"Drupal: /{path}",
                                 url=f"{scanner.base_url}/{path}",
                                 evidence=f"HTTP {r.status_code}")
        time.sleep(0.05)


# --- 4. SSL/TLS проверки ---

def check_ssl(scanner: Scanner):
    section("SSL/TLS проверки")

    parsed = urlparse(scanner.base_url)
    if parsed.scheme != "https":
        scanner.add_finding(
            "HTTP вместо HTTPS",
            "high",
            "Сайт не использует HTTPS.",
            remediation="Переведи сайт на HTTPS и настрой редирект."
        )
        return

    # Проверяем редирект с HTTP на HTTPS
    http_url = scanner.base_url.replace("https://", "http://")
    try:
        r = requests.get(http_url, timeout=5, verify=False,
                         allow_redirects=False)
        if r.status_code not in (301, 302, 307, 308):
            scanner.add_finding(
                "Нет редиректа HTTP → HTTPS",
                "medium",
                f"HTTP возвращает {r.status_code} вместо редиректа на HTTPS.",
                evidence=f"HTTP {r.status_code}",
                remediation="Настрой 301 редирект с HTTP на HTTPS."
            )
        else:
            log(f"  HTTP → HTTPS редирект: {r.status_code}", "ok")
    except Exception:
        pass

    # Проверяем сертификат
    try:
        import ssl, socket
        host = parsed.hostname
        port = parsed.port or 443
        ctx  = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # Дата истечения
                not_after = cert.get("notAfter", "")
                if not_after:
                    from datetime import datetime as dt
                    exp = dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - dt.now()).days
                    if days_left < 0:
                        scanner.add_finding(
                            "SSL сертификат истёк",
                            "critical",
                            f"Сертификат истёк {days_left*-1} дней назад.",
                            evidence=f"notAfter: {not_after}"
                        )
                    elif days_left < 30:
                        scanner.add_finding(
                            f"SSL сертификат истекает через {days_left} дней",
                            "medium",
                            "Обнови сертификат.",
                            evidence=f"notAfter: {not_after}"
                        )
                    else:
                        log(f"  Сертификат действителен ещё {days_left} дней", "ok")
    except ssl.SSLCertVerificationError:
        scanner.add_finding(
            "SSL сертификат невалиден",
            "high",
            "Сертификат не прошёл проверку (самоподписанный или истёк).",
            remediation="Установи валидный SSL сертификат."
        )
    except Exception as e:
        log(f"  SSL проверка: {e}", "warn")


# --- 5. Открытые редиректы ---

def check_open_redirect(scanner: Scanner):
    section("Open Redirect")

    redirect_params = [
        "redirect", "redirect_to", "redirect_url", "url", "next",
        "return", "return_url", "returnUrl", "ReturnUrl", "goto",
        "destination", "dest", "target", "link", "to", "from",
        "callback", "continue", "forward", "location",
    ]

    test_domain = "evil.example.com"
    test_urls   = [
        f"https://{test_domain}",
        f"http://{test_domain}",
        f"//{test_domain}",
        f"https://{test_domain}/path",
    ]

    found = []
    for param in redirect_params:
        for test_url in test_urls[:2]:  # Не перебираем всё чтобы не нагружать
            url = f"{scanner.base_url}/?{param}={requests.utils.quote(test_url)}"
            r = scanner.get(full_url=url, allow_redirects=False)
            if r and r.status_code in (301, 302, 307, 308):
                location = r.headers.get("location", "")
                if test_domain in location or test_url in location:
                    found.append({"param": param, "url": url, "location": location})
                    scanner.add_finding(
                        f"Open Redirect через параметр ?{param}=",
                        "medium",
                        f"Параметр {param} перенаправляет на внешний домен.",
                        url=url,
                        evidence=f"Location: {location}",
                        remediation="Валидируй redirect URL — разрешай только внутренние пути."
                    )
                    break
        time.sleep(0.1)

    if not found:
        log("Open Redirect: не обнаружено", "ok")


# --- 6. Проверка методов HTTP ---

def check_http_methods(scanner: Scanner):
    section("HTTP Methods")

    dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]

    try:
        r = requests.options(
            scanner.base_url,
            verify=False,
            timeout=scanner.timeout,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        allow = r.headers.get("Allow", r.headers.get("Access-Control-Allow-Methods", ""))

        if allow:
            log(f"Allow: {allow}", "info")
            enabled = [m for m in dangerous_methods if m in allow.upper()]
            if enabled:
                scanner.add_finding(
                    f"Опасные HTTP методы: {', '.join(enabled)}",
                    "medium",
                    f"Методы {enabled} разрешены.",
                    evidence=f"Allow: {allow}",
                    remediation="Отключи ненужные HTTP методы на сервере."
                )

        # TRACE метод (XST атака)
        r_trace = requests.request(
            "TRACE", scanner.base_url,
            verify=False, timeout=5,
            headers={"User-Agent": "Mozilla/5.0",
                     "X-Custom-Header": "xst-test-12345"}
        )
        if (r_trace.status_code == 200 and
            "xst-test-12345" in r_trace.text):
            scanner.add_finding(
                "HTTP TRACE включён (XST уязвимость)",
                "low",
                "TRACE метод отражает заголовки — Cross-Site Tracing (XST).",
                evidence=r_trace.text[:200],
                remediation="Отключи TRACE метод в конфигурации сервера."
            )

    except Exception as e:
        log(f"HTTP methods check: {e}", "warn")


# --- 7. Анализ контента на чувствительные данные ---

def check_content_leaks(scanner: Scanner):
    section("Content Analysis")

    pages_to_check = ["", "about", "contact", "help", "faq"]

    # Паттерны для поиска утечек
    patterns = {
        "email":       r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        "ip_internal": r'\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b',
        "aws_key":     r'AKIA[0-9A-Z]{16}',
        "api_key":     r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9\-_]{20,})',
        "jwt":         r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        "private_key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        "password_in_html": r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
        "sql_error":   r'(?:SQL syntax|mysql_fetch|ORA-\d+|PG::SyntaxError|sqlite3\.OperationalError)',
        "stack_trace": r'(?:at [a-zA-Z]+\.[a-zA-Z]+\(|Traceback \(most recent|Exception in thread)',
        "php_error":   r'(?:Parse error:|Fatal error:|Warning:|Notice:).{10,100}in\s+/[^\s]+\.php',
        "path_disclosure": r'(?:/var/www|/home/\w+|/usr/local|C:\\(?:inetpub|Users|wamp|xampp))',
    }

    all_found = {}

    for page in pages_to_check:
        r = scanner.get(page)
        if not r or r.status_code != 200:
            continue

        for pat_name, pattern in patterns.items():
            matches = re.findall(pattern, r.text, re.IGNORECASE)
            if matches:
                unique = list(set(matches[:5]))  # первые 5 уникальных
                if pat_name not in all_found:
                    all_found[pat_name] = []
                all_found[pat_name].extend(unique)

        time.sleep(0.1)

    # Формируем находки
    severity_map = {
        "private_key":     "critical",
        "aws_key":         "critical",
        "password_in_html":"high",
        "sql_error":       "high",
        "jwt":             "high",
        "api_key":         "high",
        "stack_trace":     "medium",
        "php_error":       "medium",
        "path_disclosure": "medium",
        "ip_internal":     "low",
        "email":           "info",
    }

    titles = {
        "private_key":     "Private Key в HTML",
        "aws_key":         "AWS Access Key в HTML",
        "password_in_html":"Пароль в HTML коде",
        "sql_error":       "SQL ошибка в ответе",
        "jwt":             "JWT токен в HTML",
        "api_key":         "API ключ в HTML",
        "stack_trace":     "Stack trace в ответе",
        "php_error":       "PHP ошибка в ответе",
        "path_disclosure": "Раскрытие пути файловой системы",
        "ip_internal":     "Внутренний IP адрес в ответе",
        "email":           "Email адреса в ответе",
    }

    for pat_name, matches in all_found.items():
        unique = list(set(matches))[:5]
        scanner.add_finding(
            titles.get(pat_name, pat_name),
            severity_map.get(pat_name, "info"),
            f"Найдено {len(matches)} вхождений паттерна '{pat_name}'.",
            evidence=", ".join(str(m) for m in unique[:3]),
            remediation="Удали чувствительные данные из публичного контента."
        )

    if not all_found:
        log("Утечек в контенте не обнаружено", "ok")


# --- 8. Проверка аутентификации ---

def check_auth(scanner: Scanner):
    section("Authentication Checks")

    login_paths = [
        "login", "admin", "admin/login", "administrator",
        "wp-login.php", "user/login", "signin", "auth/login",
        "panel", "dashboard", "manage", "cp",
    ]

    for path in login_paths:
        r = scanner.get(path)
        if not r or r.status_code not in (200, 301, 302):
            continue

        url = f"{scanner.base_url}/{path}"

        # Проверяем базовую аутентификацию
        if r.status_code == 401:
            auth_header = r.headers.get("WWW-Authenticate", "")
            scanner.add_finding(
                f"Basic Auth на /{path}",
                "medium",
                "Basic Authentication — пароль передаётся в base64.",
                url=url,
                evidence=f"WWW-Authenticate: {auth_header}",
            )

        # Ищем форму логина
        if r.status_code == 200 and "password" in r.text.lower():
            log(f"  Форма логина: {url}", "warn")

            # Проверяем отсутствие CSRF токена в форме
            if ("csrf" not in r.text.lower() and
                "token" not in r.text.lower() and
                "_wpnonce" not in r.text):
                scanner.add_finding(
                    f"Форма логина без CSRF токена: /{path}",
                    "medium",
                    "Форма входа не содержит CSRF защиты.",
                    url=url,
                    remediation="Добавь CSRF токен в форму."
                )

        time.sleep(0.1)


# --- 9. Директорный листинг ---

def check_directory_listing(scanner: Scanner):
    section("Directory Listing")

    dirs_to_check = [
        "uploads", "images", "files", "static", "assets",
        "backup", "backups", "logs", "tmp", "temp", "data",
        "css", "js", "scripts", "includes", "lib",
    ]

    for d in dirs_to_check:
        r = scanner.get(d + "/")
        if not r or r.status_code != 200:
            continue

        content = r.text.lower()
        if any(marker in content for marker in
               ["index of /", "directory listing", "parent directory",
                "[to parent directory]", "last modified"]):
            scanner.add_finding(
                f"Directory Listing включён: /{d}/",
                "medium",
                f"Директория /{d}/ показывает список файлов.",
                url=f"{scanner.base_url}/{d}/",
                evidence=f"HTTP 200, найден маркер листинга",
                remediation="Отключи directory listing в конфиге сервера."
            )
            log(f"  Directory listing: /{d}/", "warn")

        time.sleep(0.05)


# =============================================================================
# ИТОГОВЫЙ ОТЧЁТ
# =============================================================================

def generate_report(scanner: Scanner, out_dir: Path):
    section("Итоговый отчёт")

    findings = scanner.findings
    out_dir.mkdir(parents=True, exist_ok=True)

    # Группируем по severity
    by_sev = {}
    for f in findings:
        sev = f["severity"]
        by_sev.setdefault(sev, []).append(f)

    counts = {
        "critical": len(by_sev.get("critical", [])),
        "high":     len(by_sev.get("high",     [])),
        "medium":   len(by_sev.get("medium",   [])),
        "low":      len(by_sev.get("low",      [])),
        "info":     len(by_sev.get("info",     [])),
    }

    # Rich таблица
    if HAS_RICH:
        table = Table(title="Vulnerability Summary", header_style="bold cyan")
        table.add_column("Severity", width=10)
        table.add_column("Count",    width=8, justify="right")
        sev_styles = {
            "critical": "bold red",
            "high":     "red",
            "medium":   "yellow",
            "low":      "cyan",
            "info":     "dim",
        }
        for sev, count in counts.items():
            if count:
                table.add_row(
                    f"[{sev_styles[sev]}]{sev.upper()}[/{sev_styles[sev]}]",
                    f"[{sev_styles[sev]}]{count}[/{sev_styles[sev]}]"
                )
        console.print("\n")
        console.print(table)

    # Markdown отчёт
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# Vulnerability Scan Report",
        f"**URL:** {scanner.base_url}",
        f"**Дата:** {ts}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev, cnt in counts.items():
        if cnt:
            lines.append(f"| {sev.upper()} | {cnt} |")
    lines.append("")

    for sev in ["critical", "high", "medium", "low", "info"]:
        sev_findings = by_sev.get(sev, [])
        if not sev_findings:
            continue

        lines.append(f"## {sev.upper()} ({len(sev_findings)})")
        lines.append("")

        for f in sev_findings:
            lines += [
                f"### {f['title']}",
                f"**URL:** {f['url']}",
                f"**Description:** {f['description']}",
            ]
            if f.get("evidence"):
                lines.append(f"**Evidence:** `{f['evidence'][:200]}`")
            if f.get("remediation"):
                lines.append(f"**Remediation:** {f['remediation']}")
            lines.append("")

    report_file = out_dir / "vuln_scan_report.md"
    report_file.write_text("\n".join(lines))
    log(f"Markdown отчёт: {report_file}", "ok")

    # JSON findings
    json_file = out_dir / "findings.json"
    save_json(findings, json_file)
    log(f"JSON findings:  {json_file}", "ok")

    # Краткий итог
    total = len(findings)
    critical_high = counts["critical"] + counts["high"]
    log(f"Всего находок: {total} "
        f"(Critical/High: {critical_high})", "ok" if critical_high == 0 else "warn")

    return report_file


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="vuln_scan.py — сканер веб-уязвимостей",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python vuln_scan.py -u https://target.com
  python vuln_scan.py -u https://target.com --full
  python vuln_scan.py -u https://target.com --proxy http://127.0.0.1:8080
  python vuln_scan.py -u https://target.com --cookies "session=abc123"
  python vuln_scan.py -u https://target.com --out ~/loot/target
        """
    )
    p.add_argument("-u", "--url",     required=True)
    p.add_argument("--out",           default="")
    p.add_argument("--proxy",         default="")
    p.add_argument("--timeout",       type=int, default=10)
    p.add_argument("--cookies",       default="",
                   help="Cookies: 'key=val; key2=val2'")
    p.add_argument("-H", "--header",  action="append", default=[],
                   help="Доп. заголовок: 'Authorization: Bearer TOKEN'")
    p.add_argument("--full",          action="store_true",
                   help="Полный режим (все проверки)")
    p.add_argument("--skip-headers",  action="store_true")
    p.add_argument("--skip-info",     action="store_true")
    p.add_argument("--skip-cms",      action="store_true")
    p.add_argument("--skip-ssl",      action="store_true")
    p.add_argument("--skip-content",  action="store_true")
    return p.parse_args()


def main():
    args = parse_args()

    # Cookies
    cookies = {}
    if args.cookies:
        for part in args.cookies.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()

    # Headers
    extra_headers = {}
    for h in args.header:
        if ":" in h:
            k, _, v = h.partition(":")
            extra_headers[k.strip()] = v.strip()

    # Output dir
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.out:
        out_dir = Path(args.out)
    else:
        parsed = urlparse(normalize_url(args.url))
        safe = parsed.netloc.replace(":", "_")
        out_dir = TOOLKIT_DIR / "loot" / f"vuln_{safe}_{ts}"

    scanner = Scanner(
        args.url,
        timeout=args.timeout,
        proxy=args.proxy or None,
        headers=extra_headers,
        cookies=cookies,
    )

    if HAS_RICH:
        console.print(Panel.fit(
            f"[bold cyan]vuln_scan.py[/bold cyan]\n"
            f"[green]URL:[/green]    {scanner.base_url}\n"
            f"[green]Proxy:[/green]  {args.proxy or 'нет'}\n"
            f"[green]Output:[/green] {out_dir}",
            title="Standoff 365 Toolkit — Vuln Scan",
            border_style="cyan"
        ))

    # Запуск модулей
    if not args.skip_ssl:
        check_ssl(scanner)

    if not args.skip_headers:
        check_security_headers(scanner)

    if not args.skip_info:
        check_info_disclosure(scanner)

    if not args.skip_cms:
        check_cms(scanner)

    check_http_methods(scanner)
    check_directory_listing(scanner)

    if not args.skip_content:
        check_content_leaks(scanner)

    if args.full:
        check_open_redirect(scanner)
        check_auth(scanner)

    generate_report(scanner, out_dir)


if __name__ == "__main__":
    main()