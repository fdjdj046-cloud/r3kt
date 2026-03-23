#!/usr/bin/env python3
"""
fuzzer.py — веб-фаззер для директорий, параметров, vhost
Standoff 365 Toolkit

Использование:
  python fuzzer.py dir -u https://target.com
  python fuzzer.py dir -u https://target.com -w /path/to/wordlist.txt
  python fuzzer.py params -u https://target.com/page?FUZZ=test
  python fuzzer.py vhost -u https://target.com -w subdomains.txt
  python fuzzer.py fuzz -u https://target.com/page?id=FUZZ -w ids.txt
"""

import argparse
import asyncio
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    print("[!] pip install httpx")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None

# =============================================================================
# Конфигурация
# =============================================================================

TOOLKIT_DIR = Path.home() / "standoff-toolkit"
WORDLISTS   = TOOLKIT_DIR / "wordlists"

# Дефолтные wordlists (ищем в порядке приоритета)
DEFAULT_WORDLISTS = {
    "dirs": [
        WORDLISTS / "SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        WORDLISTS / "SecLists/Discovery/Web-Content/common.txt",
        Path("/usr/share/wordlists/dirb/common.txt"),
        Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
    ],
    "params": [
        WORDLISTS / "SecLists/Discovery/Web-Content/burp-parameter-names.txt",
        WORDLISTS / "SecLists/Discovery/Web-Content/common-http-request-headers.txt",
    ],
    "vhosts": [
        WORDLISTS / "SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
        WORDLISTS / "SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt",
    ],
    "fuzz": [
        WORDLISTS / "SecLists/Fuzzing/fuzz-Bo0oM.txt",
        WORDLISTS / "SecLists/Fuzzing/special-chars.txt",
    ],
}

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

INTERESTING_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".cgi",
    ".bak", ".backup", ".old", ".orig", ".save", ".tmp",
    ".log", ".conf", ".config", ".cfg", ".ini", ".env",
    ".xml", ".yaml", ".yml", ".json", ".sql", ".db",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".key", ".pem", ".crt", ".pfx",
]

INTERESTING_PATHS = [
    "admin", "administrator", "manage", "management", "dashboard",
    "panel", "control", "console", "backend", "cms",
    "api", "v1", "v2", "graphql", "swagger", "openapi",
    "login", "signin", "auth", "oauth", "sso", "ldap",
    "upload", "uploads", "files", "backup", "backups",
    "config", "configs", "settings", "setup", "install",
    "phpinfo", "info", "debug", "test", "dev", "staging",
    ".git", ".svn", ".env", ".htaccess", "web.config",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "wp-admin", "wp-login.php", "wp-config.php",
    "joomla", "drupal", "typo3",
    "jenkins", "gitlab", "grafana", "kibana", "elastic",
    "phpmyadmin", "adminer", "dbadmin",
    "actuator", "actuator/env", "actuator/health",
    "server-status", "server-info",
]


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

def save_json(data, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def save_lines(lines, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(str(l) for l in lines) + "\n")

def find_wordlist(wl_type="dirs"):
    for path in DEFAULT_WORDLISTS.get(wl_type, []):
        if Path(path).exists():
            return Path(path)
    return None

def load_wordlist(path):
    p = Path(path)
    if not p.exists():
        log(f"Wordlist не найден: {path}", "err")
        sys.exit(1)
    words = []
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(line)
    log(f"Wordlist: {p.name} ({len(words)} слов)", "ok")
    return words

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def is_interesting_status(code, filter_codes=None):
    if filter_codes:
        return code in filter_codes
    return code in (200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500)

def is_interesting_path(path):
    path_lower = path.lower()
    for p in INTERESTING_PATHS:
        if p in path_lower:
            return True
    for ext in INTERESTING_EXTENSIONS:
        if path_lower.endswith(ext):
            return True
    return False


# =============================================================================
# HTTP клиент
# =============================================================================

class HTTPClient:
    def __init__(self, headers=None, timeout=10, proxy=None,
                 verify_ssl=False, follow_redirects=False):
        self.headers        = {**DEFAULT_HEADERS, **(headers or {})}
        self.timeout        = timeout
        self.proxy          = proxy
        self.verify_ssl     = verify_ssl
        self.follow_redirects = follow_redirects
        self._client        = None

    def __enter__(self):
        if HAS_HTTPX:
            self._client = httpx.Client(
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                proxy=self.proxy if self.proxy else None,
            )
        return self

    def __exit__(self, *args):
        if self._client:
            self._client.close()

    def get(self, url, extra_headers=None):
        headers = {**self.headers, **(extra_headers or {})}
        try:
            if HAS_HTTPX and self._client:
                r = self._client.get(url, headers=extra_headers or {})
                return {
                    "url":     str(r.url),
                    "status":  r.status_code,
                    "length":  len(r.content),
                    "headers": dict(r.headers),
                    "body":    r.text[:2000],
                    "error":   None,
                }
            elif HAS_REQUESTS:
                import requests as req
                r = req.get(url, headers=headers, timeout=self.timeout,
                            verify=self.verify_ssl,
                            allow_redirects=self.follow_redirects)
                return {
                    "url":     r.url,
                    "status":  r.status_code,
                    "length":  len(r.content),
                    "headers": dict(r.headers),
                    "body":    r.text[:2000],
                    "error":   None,
                }
        except Exception as e:
            return {"url": url, "status": 0, "length": 0,
                    "headers": {}, "body": "", "error": str(e)}

    def post(self, url, data=None, json_data=None, extra_headers=None):
        headers = {**self.headers, **(extra_headers or {})}
        try:
            if HAS_HTTPX and self._client:
                r = self._client.post(url, data=data, json=json_data,
                                      headers=extra_headers or {})
                return {
                    "url":    str(r.url),
                    "status": r.status_code,
                    "length": len(r.content),
                    "body":   r.text[:2000],
                    "error":  None,
                }
            elif HAS_REQUESTS:
                import requests as req
                r = req.post(url, data=data, json=json_data,
                             headers=headers, timeout=self.timeout,
                             verify=self.verify_ssl)
                return {
                    "url":    r.url,
                    "status": r.status_code,
                    "length": len(r.content),
                    "body":   r.text[:2000],
                    "error":  None,
                }
        except Exception as e:
            return {"url": url, "status": 0, "length": 0,
                    "body": "", "error": str(e)}


# =============================================================================
# Получение baseline (размер ответа 404)
# =============================================================================

def get_baseline(client, base_url):
    """
    Получаем baseline — размер ответа на несуществующий путь.
    Нужно чтобы отфильтровать кастомные 404 страницы.
    """
    test_paths = [
        "/this_path_does_not_exist_12345",
        "/aabbccdd_nonexistent_xyz",
    ]
    baselines = []
    for path in test_paths:
        resp = client.get(base_url + path)
        if resp["status"] != 0:
            baselines.append({
                "status": resp["status"],
                "length": resp["length"],
            })

    if baselines:
        # Средний размер несуществующих страниц
        avg_length = sum(b["length"] for b in baselines) / len(baselines)
        baseline_status = baselines[0]["status"]
        log(f"Baseline: status={baseline_status}, avg_length={avg_length:.0f}", "info")
        return {"status": baseline_status, "avg_length": avg_length}

    return {"status": 404, "avg_length": 0}


def is_false_positive(resp, baseline, length_tolerance=50):
    """Определяем ложное срабатывание по сравнению с baseline."""
    if resp["status"] == 0:
        return True
    # Если статус совпадает с baseline И длина похожа — это кастомная 404
    if (resp["status"] == baseline["status"] and
        abs(resp["length"] - baseline["avg_length"]) < length_tolerance):
        return True
    return False


# =============================================================================
# 1. DIRECTORY / FILE FUZZING
# =============================================================================

async def _fuzz_dirs_async(base_url, all_words, baseline, filter_codes,
                            timeout, proxy, concurrency=50):
    """Асинхронное ядро fuzzer — реальный параллелизм."""
    import asyncio
    results = []
    errors  = 0
    semaphore = asyncio.Semaphore(concurrency)
    parsed = urlparse(base_url)

    async def fetch(client, word):
        nonlocal errors
        word = word.lstrip("/")
        target_url = f"{base_url}/{word}"
        async with semaphore:
            try:
                r = await client.get(target_url)
                return {
                    "url":         target_url,
                    "status":      r.status_code,
                    "length":      len(r.content),
                    "word":        word,
                    "headers":     dict(r.headers),
                    "redirect":    r.headers.get("location", ""),
                    "interesting": is_interesting_path(word),
                    "error":       None,
                }
            except Exception as e:
                errors += 1
                return {"url": target_url, "status": 0, "length": 0,
                        "word": word, "headers": {}, "redirect": "",
                        "interesting": False, "error": str(e)}

    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(
        timeout=timeout,
        verify=False,
        follow_redirects=False,
        limits=limits,
        proxy=proxy if proxy else None,
    ) as client:
        if HAS_RICH:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[cyan]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TextColumn("[green]{task.fields[hits]} hits"),
                console=console,
                transient=True
            )
            with progress:
                task = progress.add_task(
                    f"Fuzzing {parsed.netloc}",
                    total=len(all_words), hits=0
                )
                tasks = [fetch(client, w) for w in all_words]
                for coro in asyncio.as_completed(tasks):
                    resp = await coro
                    progress.update(task, advance=1)
                    if (resp["status"] != 0 and
                        not is_false_positive(resp, baseline) and
                        is_interesting_status(resp["status"], filter_codes)):
                        results.append(resp)
                        color = "green"  if resp["status"] == 200 else \
                                "yellow" if resp["status"] in (301,302,307) else \
                                "red"    if resp["status"] in (401,403) else "white"
                        progress.log(
                            f"[{color}]{resp['status']}[/{color}] "
                            f"{resp['url']} "
                            f"[dim](len:{resp['length']})[/dim]"
                            + (" ← [bold]INTERESTING[/bold]" if resp["interesting"] else "")
                        )
                        progress.update(task, hits=len(results))
        else:
            tasks = [fetch(client, w) for w in all_words]
            done = 0
            for coro in asyncio.as_completed(tasks):
                resp = await coro
                done += 1
                if done % 100 == 0:
                    print(f"  [{done}/{len(all_words)}] {len(results)} hits...", end="\r")
                if (resp["status"] != 0 and
                    not is_false_positive(resp, baseline) and
                    is_interesting_status(resp["status"], filter_codes)):
                    results.append(resp)
                    print(f"\n  [{resp['status']}] {resp['url']} (len:{resp['length']})")

    return results, errors


def fuzz_dirs(url, wordlist_path=None, threads=50, extensions=None,
              filter_codes=None, timeout=10, proxy=None,
              out_dir=None, recursive=False):
    section(f"Directory Fuzzing: {url}")

    base_url = normalize_url(url)

    if not wordlist_path:
        wordlist_path = find_wordlist("dirs")
        if not wordlist_path:
            log("Wordlist не найден! Запусти setup.sh", "err")
            sys.exit(1)

    words = load_wordlist(wordlist_path)

    all_words = list(words)
    if extensions:
        for word in words:
            if "." not in word:
                for ext in extensions:
                    ext = ext if ext.startswith(".") else f".{ext}"
                    all_words.append(f"{word}{ext}")

    log(f"Слов для проверки: {len(all_words)}", "info")
    log(f"Параллельных запросов: {threads}", "info")

    start = time.time()

    # Получаем baseline синхронно
    with HTTPClient(timeout=timeout, proxy=proxy) as client:
        baseline = get_baseline(client, base_url)

    # Запускаем async fuzzing
    results, errors = asyncio.run(
        _fuzz_dirs_async(base_url, all_words, baseline,
                         filter_codes, timeout, proxy, concurrency=threads)
    )

    elapsed = time.time() - start
    _print_dir_results(results, elapsed, errors)

    if out_dir:
        _save_results(results, Path(out_dir), "dir_fuzz")

    return results


def _print_dir_results(results, elapsed, errors):
    log(f"Завершено за {elapsed:.1f}с | "
        f"Найдено: {len(results)} | Ошибок: {errors}", "ok")

    if not results:
        log("Ничего не найдено", "warn")
        return

    if HAS_RICH:
        table = Table(show_header=True, header_style="bold cyan",
                      title=f"Результаты ({len(results)})")
        table.add_column("Статус",  width=8)
        table.add_column("URL",     width=55)
        table.add_column("Длина",   width=8, justify="right")
        table.add_column("Заметки", width=15)

        status_colors = {
            200: "green", 201: "green", 204: "green",
            301: "yellow", 302: "yellow", 307: "yellow",
            401: "red", 403: "red",
            500: "bold red",
        }

        for r in sorted(results, key=lambda x: (x["status"], x["url"])):
            color = status_colors.get(r["status"], "white")
            notes = []
            if r.get("interesting"):
                notes.append("★ interesting")
            if r.get("redirect"):
                notes.append(f"→ {r['redirect'][:20]}")
            table.add_row(
                f"[{color}]{r['status']}[/{color}]",
                r["url"],
                str(r["length"]),
                " ".join(notes),
            )
        console.print(table)
    else:
        for r in sorted(results, key=lambda x: x["status"]):
            print(f"  [{r['status']}] {r['url']} (len:{r['length']})")


# =============================================================================
# 2. PARAMETER FUZZING (поиск скрытых параметров)
# =============================================================================

def fuzz_params(url, wordlist_path=None, method="GET",
                timeout=10, proxy=None, out_dir=None):
    """
    Ищем скрытые HTTP параметры.
    Сравниваем ответ без параметра с ответом с каждым параметром.
    """
    section(f"Parameter Fuzzing: {url}")

    base_url = normalize_url(url)

    if not wordlist_path:
        wordlist_path = find_wordlist("params")
        if not wordlist_path:
            log("Wordlist для параметров не найден", "err")
            # Используем встроенный мини-список
            params = _builtin_param_list()
        else:
            params = load_wordlist(wordlist_path)
    else:
        params = load_wordlist(wordlist_path)

    log(f"Параметров для проверки: {len(params)}", "info")

    results = []

    with HTTPClient(timeout=timeout, proxy=proxy) as client:
        # Baseline ответ
        baseline = client.get(base_url)
        baseline_len    = baseline["length"]
        baseline_status = baseline["status"]
        log(f"Baseline: status={baseline_status}, length={baseline_len}", "info")

        if HAS_RICH:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Parameter fuzzing..."),
                BarColumn(),
                TaskProgressColumn(),
                console=console, transient=True
            )
            with progress:
                task = progress.add_task("", total=len(params))

                for param in params:
                    if method.upper() == "GET":
                        sep = "&" if "?" in base_url else "?"
                        test_url = f"{base_url}{sep}{param}=test123"
                        resp = client.get(test_url)
                    else:
                        resp = client.post(base_url, data={param: "test123"})

                    # Ищем разницу в ответе
                    len_diff = abs(resp["length"] - baseline_len)
                    status_changed = resp["status"] != baseline_status

                    if (len_diff > 50 or status_changed) and resp["status"] != 0:
                        hit = {
                            "param":          param,
                            "status":         resp["status"],
                            "length":         resp["length"],
                            "baseline_length": baseline_len,
                            "length_diff":    len_diff,
                            "status_changed": status_changed,
                            "url":            test_url if method == "GET" else base_url,
                        }
                        results.append(hit)
                        progress.log(
                            f"[green]PARAM FOUND[/green]: {param} "
                            f"(status:{resp['status']}, len_diff:{len_diff})"
                        )

                    progress.update(task, advance=1)
        else:
            for i, param in enumerate(params):
                if i % 50 == 0:
                    print(f"  [{i}/{len(params)}]...", end="\r")
                sep = "&" if "?" in base_url else "?"
                test_url = f"{base_url}{sep}{param}=test123"
                resp = client.get(test_url)
                len_diff = abs(resp["length"] - baseline_len)
                if len_diff > 50 or resp["status"] != baseline_status:
                    results.append({"param": param, "status": resp["status"],
                                    "length_diff": len_diff})
                    print(f"\n  PARAM: {param} (diff:{len_diff})")

    if results:
        log(f"Найдено {len(results)} параметров!", "ok")
        for r in results:
            log(f"  ?{r['param']}= "
                f"(status:{r['status']}, diff:{r['length_diff']})", "ok")
        if out_dir:
            _save_results(results, Path(out_dir), "params")
    else:
        log("Скрытых параметров не найдено", "warn")

    return results


def _builtin_param_list():
    """Встроенный список популярных параметров."""
    return [
        "id", "user", "username", "email", "password", "pass", "pwd",
        "token", "key", "api_key", "apikey", "secret", "auth", "access_token",
        "redirect", "url", "next", "return", "returnUrl", "callback",
        "file", "path", "dir", "folder", "page", "include", "load",
        "debug", "test", "dev", "admin", "action", "cmd", "command",
        "q", "query", "search", "s", "keyword",
        "lang", "language", "locale",
        "format", "output", "type", "mode",
        "year", "month", "day", "date",
        "limit", "offset", "page", "per_page", "count",
        "sort", "order", "orderby", "filter",
        "ref", "source", "from", "to",
        "uid", "pid", "sid", "cid", "oid",
        "data", "payload", "body", "content",
        "name", "title", "description", "message", "text",
    ]


# =============================================================================
# 3. VIRTUAL HOST FUZZING
# =============================================================================

def fuzz_vhosts(url, wordlist_path=None, timeout=10,
                proxy=None, out_dir=None, filter_codes=None):
    """
    Ищем виртуальные хосты через манипуляцию заголовком Host.
    """
    section(f"VHost Fuzzing: {url}")

    base_url = normalize_url(url)
    parsed   = urlparse(base_url)
    base_host = parsed.netloc

    # Определяем базовый домен
    parts = base_host.split(".")
    if len(parts) >= 2:
        base_domain = ".".join(parts[-2:])
    else:
        base_domain = base_host

    if not wordlist_path:
        wordlist_path = find_wordlist("vhosts")
        if not wordlist_path:
            log("Wordlist для vhost не найден", "err")
            sys.exit(1)

    subdomains = load_wordlist(wordlist_path)
    log(f"Субдоменов для проверки: {len(subdomains)}", "info")

    results = []

    with HTTPClient(timeout=timeout, proxy=proxy) as client:
        # Baseline с оригинальным хостом
        baseline = client.get(base_url)
        baseline_len    = baseline["length"]
        baseline_status = baseline["status"]
        log(f"Baseline: status={baseline_status}, length={baseline_len}", "info")

        if HAS_RICH:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[cyan]VHost fuzzing..."),
                BarColumn(),
                TaskProgressColumn(),
                TextColumn("[green]{task.fields[hits]} hits"),
                console=console, transient=True
            )
            with progress:
                task = progress.add_task("", total=len(subdomains), hits=0)

                for sub in subdomains:
                    vhost = f"{sub}.{base_domain}"
                    resp  = client.get(base_url, extra_headers={"Host": vhost})

                    len_diff       = abs(resp["length"] - baseline_len)
                    status_changed = resp["status"] != baseline_status

                    if (len_diff > 100 or status_changed) and resp["status"] != 0:
                        if not (filter_codes and resp["status"] not in filter_codes):
                            hit = {
                                "vhost":          vhost,
                                "status":         resp["status"],
                                "length":         resp["length"],
                                "length_diff":    len_diff,
                                "status_changed": status_changed,
                            }
                            results.append(hit)
                            progress.log(
                                f"[green]VHOST[/green]: {vhost} "
                                f"(status:{resp['status']}, len:{resp['length']})"
                            )
                            progress.update(task, hits=len(results))

                    progress.update(task, advance=1)
        else:
            for i, sub in enumerate(subdomains):
                vhost = f"{sub}.{base_domain}"
                resp  = client.get(base_url, extra_headers={"Host": vhost})
                len_diff = abs(resp["length"] - baseline_len)
                if len_diff > 100 or resp["status"] != baseline_status:
                    results.append({"vhost": vhost, "status": resp["status"]})
                    print(f"  VHOST: {vhost} [{resp['status']}]")

    if results:
        log(f"Найдено {len(results)} vhost!", "ok")
        for r in results:
            log(f"  {r['vhost']} (status:{r['status']}, len:{r['length']})", "ok")
        if out_dir:
            _save_results(results, Path(out_dir), "vhosts")
    else:
        log("VHost не найдено", "warn")

    return results


# =============================================================================
# 4. GENERIC FUZZ (FUZZ placeholder в URL/Headers/Body)
# =============================================================================

def fuzz_generic(url, wordlist_path=None, method="GET",
                 data=None, headers=None, timeout=10,
                 proxy=None, filter_codes=None,
                 filter_length=None, out_dir=None):
    """
    Универсальный фаззер — заменяет FUZZ в URL/данных/заголовках.
    Аналог ffuf.
    """
    section(f"Generic Fuzz: {url}")

    if "FUZZ" not in url and "FUZZ" not in str(data or ""):
        log("Нет FUZZ placeholder в URL или данных!", "err")
        log("Пример: python fuzzer.py fuzz -u 'https://target.com/page?id=FUZZ' -w ids.txt", "info")
        sys.exit(1)

    if not wordlist_path:
        wordlist_path = find_wordlist("fuzz")
        if not wordlist_path:
            log("Wordlist не найден", "err")
            sys.exit(1)

    words = load_wordlist(wordlist_path)
    log(f"Слов: {len(words)}", "info")

    results = []
    extra_headers = headers or {}

    with HTTPClient(timeout=timeout, proxy=proxy) as client:
        # Baseline
        baseline_url  = url.replace("FUZZ", "BASELINE_FUZZ_TEST_12345")
        baseline_data = data.replace("FUZZ", "BASELINE_FUZZ_TEST_12345") if data else None
        baseline_resp = client.get(baseline_url) if method == "GET" else \
                        client.post(url, data=baseline_data)
        baseline_len  = baseline_resp["length"]
        log(f"Baseline length: {baseline_len}", "info")

        if HAS_RICH:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Fuzzing..."),
                BarColumn(),
                TaskProgressColumn(),
                TextColumn("[green]{task.fields[hits]} hits"),
                console=console, transient=True
            )
            with progress:
                task = progress.add_task("", total=len(words), hits=0)

                for word in words:
                    test_url  = url.replace("FUZZ", word)
                    test_data = data.replace("FUZZ", word) if data else None

                    if method.upper() == "GET":
                        resp = client.get(test_url, extra_headers=extra_headers)
                    else:
                        resp = client.post(url, data=test_data,
                                           extra_headers=extra_headers)

                    if resp["status"] == 0:
                        continue

                    # Фильтрация
                    if filter_codes and resp["status"] not in filter_codes:
                        progress.update(task, advance=1)
                        continue
                    if filter_length and abs(resp["length"] - baseline_len) < filter_length:
                        progress.update(task, advance=1)
                        continue
                    if not filter_codes and not is_interesting_status(resp["status"]):
                        progress.update(task, advance=1)
                        continue

                    hit = {
                        "word":   word,
                        "url":    test_url,
                        "status": resp["status"],
                        "length": resp["length"],
                        "diff":   abs(resp["length"] - baseline_len),
                    }
                    results.append(hit)

                    color = "green" if resp["status"] == 200 else \
                            "yellow" if resp["status"] in (301,302,307) else \
                            "red"
                    progress.log(
                        f"[{color}]{resp['status']}[/{color}] "
                        f"[cyan]{word}[/cyan] "
                        f"[dim]len:{resp['length']} diff:{hit['diff']}[/dim]"
                    )
                    progress.update(task, hits=len(results))
                    progress.update(task, advance=1)
        else:
            for i, word in enumerate(words):
                if i % 100 == 0:
                    print(f"  [{i}/{len(words)}] {len(results)} hits...", end="\r")
                test_url = url.replace("FUZZ", word)
                resp = client.get(test_url)
                if resp["status"] != 0 and is_interesting_status(resp["status"]):
                    results.append({"word": word, "url": test_url,
                                    "status": resp["status"], "length": resp["length"]})
                    print(f"\n  [{resp['status']}] {word} (len:{resp['length']})")

    log(f"Найдено: {len(results)}", "ok")
    if out_dir:
        _save_results(results, Path(out_dir), "generic_fuzz")

    return results


# =============================================================================
# 5. EXTENSION FUZZING
# =============================================================================

def fuzz_extensions(url, base_path, timeout=10, proxy=None, out_dir=None):
    """Перебираем расширения для известного пути."""
    section(f"Extension Fuzzing: {url}/{base_path}.*")

    base_url = normalize_url(url)
    results  = []

    # Убираем расширение если есть
    base_name = base_path.rsplit(".", 1)[0] if "." in base_path else base_path

    extensions = INTERESTING_EXTENSIONS + [
        ".html", ".htm", ".txt", ".md",
        ".php5", ".php7", ".phtml",
        ".asp", ".aspx", ".ashx", ".asmx",
        ".jsp", ".jspx", ".jsf",
    ]

    log(f"Расширений для проверки: {len(extensions)}", "info")

    with HTTPClient(timeout=timeout, proxy=proxy) as client:
        for ext in extensions:
            test_url = f"{base_url}/{base_name}{ext}"
            resp = client.get(test_url)

            if resp["status"] not in (0, 404) and resp["length"] > 0:
                results.append({
                    "url":    test_url,
                    "status": resp["status"],
                    "length": resp["length"],
                    "ext":    ext,
                })
                log(f"  [{resp['status']}] {test_url} (len:{resp['length']})", "ok")

    if results:
        log(f"Найдено {len(results)} файлов!", "ok")
        if out_dir:
            _save_results(results, Path(out_dir), "extensions")
    else:
        log("Ничего не найдено", "warn")

    return results


# =============================================================================
# Сохранение результатов
# =============================================================================

def _save_results(results, out_dir, prefix):
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # JSON
    json_file = out_dir / f"{prefix}_{ts}.json"
    save_json(results, json_file)

    # Только URL / хиты
    if results and "url" in results[0]:
        urls = [r["url"] for r in results]
        save_lines(urls, out_dir / f"{prefix}_{ts}_urls.txt")

    log(f"Результаты сохранены: {json_file}", "ok")


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="fuzzer.py — веб-фаззер",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Directory fuzzing
  python fuzzer.py dir -u https://target.com
  python fuzzer.py dir -u https://target.com -w /path/to/wordlist.txt -x php,bak

  # Parameter discovery
  python fuzzer.py params -u https://target.com/page

  # VHost fuzzing
  python fuzzer.py vhost -u https://10.0.0.1 -w subdomains.txt

  # Generic (FUZZ placeholder)
  python fuzzer.py fuzz -u 'https://target.com/page?id=FUZZ' -w ids.txt
  python fuzzer.py fuzz -u 'https://target.com/FUZZ' -w dirs.txt --fc 404

  # Extension fuzzing
  python fuzzer.py ext -u https://target.com --path backup
        """
    )

    sub = p.add_subparsers(dest="mode")

    # Общие аргументы
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-u", "--url",     required=True, help="URL цели")
    common.add_argument("-w", "--wordlist", default="",   help="Wordlist")
    common.add_argument("-t", "--threads",  type=int, default=50)
    common.add_argument("--timeout",        type=int, default=10)
    common.add_argument("--proxy",          default="",
                        help="Прокси (http://127.0.0.1:8080)")
    common.add_argument("--out",            default="",
                        help="Директория для сохранения результатов")
    common.add_argument("--fc",             default="",
                        help="Фильтр кодов (200,301,403)")
    common.add_argument("-H", "--header",   action="append", default=[],
                        help="Дополнительный заголовок (можно несколько)")

    # dir
    dir_p = sub.add_parser("dir", parents=[common], help="Directory/file fuzzing")
    dir_p.add_argument("-x", "--extensions", default="",
                       help="Расширения через запятую (php,bak,old)")
    dir_p.add_argument("-r", "--recursive", action="store_true")

    # params
    params_p = sub.add_parser("params", parents=[common],
                               help="Parameter discovery")
    params_p.add_argument("-X", "--method", default="GET",
                           choices=["GET", "POST"])

    # vhost
    sub.add_parser("vhost", parents=[common], help="VHost fuzzing")

    # fuzz (generic)
    fuzz_p = sub.add_parser("fuzz", parents=[common], help="Generic fuzzing (FUZZ)")
    fuzz_p.add_argument("-X", "--method", default="GET",
                        choices=["GET", "POST"])
    fuzz_p.add_argument("-d", "--data",   default="",
                        help="POST данные с FUZZ placeholder")
    fuzz_p.add_argument("--fl",           type=int, default=None,
                        help="Минимальная разница в длине ответа")

    # ext
    ext_p = sub.add_parser("ext", parents=[common], help="Extension fuzzing")
    ext_p.add_argument("--path", required=True, help="Базовое имя файла")

    return p.parse_args()


def main():
    if not HAS_HTTPX and not HAS_REQUESTS:
        print("[-] Нужен httpx или requests: pip install httpx")
        sys.exit(1)

    args = parse_args()

    if not args.mode:
        print("Укажи режим: dir, params, vhost, fuzz, ext")
        print("python fuzzer.py --help")
        sys.exit(1)

    # Парсим общие параметры
    url      = args.url
    wordlist = args.wordlist or None
    proxy    = args.proxy or None
    out_dir  = args.out or None
    timeout  = args.timeout

    filter_codes = None
    if args.fc:
        filter_codes = [int(c.strip()) for c in args.fc.split(",") if c.strip()]

    extra_headers = {}
    for h in getattr(args, "header", []):
        if ":" in h:
            k, _, v = h.partition(":")
            extra_headers[k.strip()] = v.strip()

    if HAS_RICH:
        console.print(Panel.fit(
            f"[bold cyan]fuzzer.py[/bold cyan]\n"
            f"[green]Режим:[/green]  {args.mode}\n"
            f"[green]URL:[/green]    {url}\n"
            f"[green]Proxy:[/green]  {proxy or 'нет'}",
            title="Standoff 365 Toolkit — Fuzzer",
            border_style="cyan"
        ))

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_dir:
        parsed = urlparse(url)
        safe_host = parsed.netloc.replace(":", "_")
        out_dir = str(
            TOOLKIT_DIR / "loot" / f"fuzz_{safe_host}_{ts}"
        )

    if args.mode == "dir":
        exts = [e.strip() for e in args.extensions.split(",") if e.strip()] \
               if args.extensions else None
        fuzz_dirs(
            url, wordlist_path=wordlist,
            extensions=exts,
            filter_codes=filter_codes,
            timeout=timeout, proxy=proxy,
            out_dir=out_dir,
            recursive=args.recursive,
        )

    elif args.mode == "params":
        fuzz_params(
            url, wordlist_path=wordlist,
            method=args.method,
            timeout=timeout, proxy=proxy,
            out_dir=out_dir,
        )

    elif args.mode == "vhost":
        fuzz_vhosts(
            url, wordlist_path=wordlist,
            timeout=timeout, proxy=proxy,
            out_dir=out_dir,
            filter_codes=filter_codes,
        )

    elif args.mode == "fuzz":
        fuzz_generic(
            url, wordlist_path=wordlist,
            method=args.method,
            data=args.data or None,
            headers=extra_headers,
            timeout=timeout, proxy=proxy,
            filter_codes=filter_codes,
            filter_length=args.fl,
            out_dir=out_dir,
        )

    elif args.mode == "ext":
        fuzz_extensions(
            url, base_path=args.path,
            timeout=timeout, proxy=proxy,
            out_dir=out_dir,
        )


if __name__ == "__main__":
    main()