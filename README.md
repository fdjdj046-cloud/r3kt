# R3KT — Recon & Exploitation Kit

```
██████╗ ██████╗ ██╗  ██╗████████╗
██╔══██╗╚════██╗██║ ██╔╝╚══██╔══╝
██████╔╝ █████╔╝█████╔╝    ██║   
██╔══██╗ ╚═══██╗██╔═██╗    ██║   
██║  ██║██████╔╝██║  ██╗   ██║   
╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   

Recon & Exploitation Kit
by GUTS @ Ynk4ts
```

> Offensive security toolkit для Standoff 365 и CTF соревнований.  
> Arch Linux. Python 3. Bash.

---

## Модули

| Модуль | Описание |
|--------|----------|
| `recon/recon.py` | Автоматизация внешней разведки — субдомены, порты, технологии, nuclei |
| `recon/osint.py` | Пассивная OSINT разведка — WHOIS, DNS, ASN, emails, GitHub, Wayback |
| `web/fuzzer.py` | Async веб-фаззер — директории, параметры, vhost, FUZZ placeholder |
| `web/vuln_scan.py` | Сканер веб-уязвимостей — заголовки, CMS, SSL, утечки, open redirect |
| `ad/ad_enum.py` | AD enumeration — пользователи, SPNs, ACL, BloodHound, CVEs |
| `ad/spray.py` | Password spraying с защитой от локаута, 4 протокола |
| `post/pivot.sh` | Туннели — Ligolo-ng, Chisel, SSH, Socat |
| `post/loot.py` | Управление находками — кредентиалы, хеши, хосты, отчёт |
| `utils/shell_upgrade.py` | Шпаргалка — reverse shells, TTY upgrade, передача файлов |
| `utils/encode.py` | Кодирование — base64, url, hex, html, hash, jwt, powershell |

---

## Быстрый старт

```bash
git clone https://github.com/fdjdj046-cloud/r3kt.git
cd r3kt
chmod +x setup.sh
./setup.sh install   # установка всех зависимостей
./setup.sh           # открыть лаунчер
```

После установки:
```bash
source ~/.bashrc
st   # алиас для быстрого запуска
```

---

## Требования

- Python 3.10+
- Go 1.21+
- sudo доступ (для установки)

---

## Структура

```
r3kt/
├── setup.sh              # лаунчер + установщик
├── recon/
│   ├── recon.py          # внешняя разведка
│   └── osint.py          # пассивный OSINT
├── web/
│   ├── fuzzer.py         # веб-фаззер
│   └── vuln_scan.py      # сканер уязвимостей
├── ad/
│   ├── ad_enum.py        # AD enumeration
│   └── spray.py          # password spraying
├── post/
│   ├── pivot.sh          # туннели
│   └── loot.py           # управление находками
└── utils/
    ├── shell_upgrade.py  # шпаргалка по шеллам
    └── encode.py         # кодирование/декодирование
```

---

## Лаунчер

```
  ╔══════════════════════════════════════════════════╗
  ║          R3KT — Recon & Exploitation Kit         ║
  ║          by GUTS @ Ynk4ts                        ║
  ╚══════════════════════════════════════════════════╝

  ── 🔍 РАЗВЕДКА ──────────────────────────────────────
  ● [ 1]  recon.py       Субдомены, порты, nuclei
  ● [ 2]  osint.py       WHOIS, DNS, emails, GitHub

  ── 🌐 ВЕБ ───────────────────────────────────────────
  ● [ 3]  fuzzer.py      Dir/param/vhost fuzzing
  ● [ 4]  vuln_scan.py   Заголовки, CMS, SSL, утечки

  ── 🏢 ACTIVE DIRECTORY ──────────────────────────────
  ● [ 5]  ad_enum.py     Users, SPNs, BloodHound, CVEs
  ● [ 6]  spray.py       Password spraying

  ── 🔑 ПОСТ-ЭКСПЛУАТАЦИЯ ─────────────────────────────
  ● [ 7]  pivot.sh       Ligolo-ng, Chisel, SSH, Socat
  ● [ 8]  loot.py        Кредентиалы, хеши, отчёт

  ── 🛠️  УТИЛИТЫ ───────────────────────────────────────
  ● [ 9]  shell_upgrade  Rev shells, TTY, file transfer
  ● [10]  encode.py      base64/url/hex/hash/jwt
```

---

## Зависимости (устанавливаются автоматически)

**Go tools:** subfinder, httpx, nuclei, naabu, dnsx, katana, ffuf, gobuster, dalfox, kerbrute, chisel

**Python:** impacket, bloodhound-python, certipy-ad, ldapdomaindump, netexec, mitm6

**Ruby:** evil-winrm

**Wordlists:** SecLists, rockyou.txt

---

## Дисклеймер

> Инструмент предназначен **только** для авторизованного тестирования безопасности,  
> CTF соревнований и образовательных целей.  
> Использование против систем без явного разрешения **незаконно**.

---

**GUTS @ Ynk4ts** | Standoff 365