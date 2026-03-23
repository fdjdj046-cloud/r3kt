<div align="center">

# 🗡️ R3KT — Recon & Exploitation Kit
**Offensive security toolkit для Standoff 365, CTF и пентеста**

[![Arch Linux](https://img.shields.io/badge/OS-Arch%20Linux-1793D1?style=for-the-badge&logo=arch-linux&logoColor=white)](#)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](#)
[![Bash](https://img.shields.io/badge/Bash-Scripting-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)](#)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](#)

```text
██████╗ ██████╗ ██╗  ██╗████████╗
██╔══██╗╚════██╗██║ ██╔╝╚══██╔══╝
██████╔╝ █████╔╝█████╔╝    ██║   
██╔══██╗ ╚═══██╗██╔═██╗    ██║   
██║  ██║██████╔╝██║  ██╗   ██║   
╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   

   by GUTS @ Ynk4ts
```

*Автоматизация рутины, фокус на эксплуатации.*

</div>

---

## 🚀 Быстрый старт

Установка займет всего пару минут. Скрипт сам подтянет все необходимые зависимости.

```bash
# 1. Клонируем репозиторий
git clone https://github.com/fdjdj046-cloud/r3kt.git
cd r3kt

# 2. Делаем лаунчер исполняемым
chmod +x setup.sh

# 3. Устанавливаем все зависимости (требуется sudo)
./setup.sh install

# 4. Запускаем лаунчер
./setup.sh
```

> **💡 Совет:** После установки перезагрузите конфиг оболочки `source ~/.bashrc` (или `.zshrc`), чтобы использовать глобальный алиас `st` для быстрого запуска тулкита из любой папки.

---

## 📦 Доступные модули

Инструмент разбит на логические категории. Каждый скрипт можно использовать как через главное меню, так и автономно.

| Категория | Модуль | Описание функционала |
| :--- | :--- | :--- |
| 🔍 **Recon** | `recon/recon.py` | Внешняя разведка: поиск субдоменов, сканирование портов, определение технологий, запуск nuclei |
| 🕵️ **OSINT** | `recon/osint.py` | Пассивный сбор: WHOIS, DNS, ASN, поиск email, утечки GitHub, Wayback Machine |
| 🌐 **Web** | `web/fuzzer.py` | Async веб-фаззер: директории, параметры, vhost, поддержка `FUZZ` плейсхолдеров |
| 🕷️ **Vuln** | `web/vuln_scan.py` | Сканер уязвимостей: анализ заголовков, детекция CMS, SSL-баги, утечки инфы, Open Redirect |
| 🏢 **AD** | `ad/ad_enum.py` | Active Directory Enum: пользователи, SPNs, сбор данных для BloodHound, проверка на CVE |
| 💦 **AD** | `ad/spray.py` | Password Spraying: умный перебор по 4 протоколам с защитой от блокировки (lockout) учетных записей |
| 🔑 **Post** | `post/pivot.sh` | Туннелирование и проброс портов: автоматизация Ligolo-ng, Chisel, SSH, Socat |
| 💰 **Loot** | `post/loot.py` | Менеджер находок: удобное хранение креденшиалов, хешей, интересных хостов и генерация отчёта |
| 🛠️ **Utils** | `utils/shell_upgrade.py` | Интерактивная шпаргалка: reverse shells, апгрейд до полноценного TTY, команды передачи файлов |
| 🧮 **Utils** | `utils/encode.py` | Швейцарский нож кодировок: Base64, URL, Hex, HTML, хэширование, JWT, PowerShell payload |

---

## 🖥️ Интерфейс лаунчера

Главное меню предоставляет быстрый доступ ко всем функциям без необходимости запоминать пути к скриптам:

```text
  ╔══════════════════════════════════════════════════╗
  ║          R3KT — Recon & Exploitation Kit         ║
  ║          by GUTS @ Ynk4ts                        ║
  ╚══════════════════════════════════════════════════╝

  ── 🔍 РАЗВЕДКА ──────────────────────────────────────
  ● [ 1]  recon.py       Субдомены, порты, nuclei
  ●[ 2]  osint.py       WHOIS, DNS, emails, GitHub

  ── 🌐 ВЕБ ───────────────────────────────────────────
  ● [ 3]  fuzzer.py      Dir/param/vhost fuzzing
  ● [ 4]  vuln_scan.py   Заголовки, CMS, SSL, утечки

  ── 🏢 ACTIVE DIRECTORY ──────────────────────────────
  ●[ 5]  ad_enum.py     Users, SPNs, BloodHound, CVEs
  ●[ 6]  spray.py       Password spraying

  ── 🔑 ПОСТ-ЭКСПЛУАТАЦИЯ ─────────────────────────────
  ● [ 7]  pivot.sh       Ligolo-ng, Chisel, SSH, Socat
  ● [ 8]  loot.py        Кредентиалы, хеши, отчёт

  ── 🛠️  УТИЛИТЫ ───────────────────────────────────────
  ●[ 9]  shell_upgrade  Rev shells, TTY, file transfer
  ● [10]  encode.py      base64/url/hex/hash/jwt
```

---

## ⚙️ Интегрированные зависимости

Скрипт установки `setup.sh install` автоматически подтягивает и настраивает топовые инструменты ИБ-индустрии:

* **Go Tools:** `subfinder`, `httpx`, `nuclei`, `naabu`, `dnsx`, `katana`, `ffuf`, `gobuster`, `dalfox`, `kerbrute`, `chisel`
* **Python Packages:** `impacket`, `bloodhound-python`, `certipy-ad`, `ldapdomaindump`, `netexec`, `mitm6`
* **Ruby:** `evil-winrm`
* **Словари (Wordlists):** `SecLists`, `rockyou.txt`

---

## 📂 Структура проекта

<details>
<summary>Посмотреть дерево директорий</summary>

```text
r3kt/
├── setup.sh              # Главный лаунчер и скрипт установки
├── recon/
│   ├── recon.py          # Автоматизация внешней разведки
│   └── osint.py          # Пассивный OSINT
├── web/
│   ├── fuzzer.py         # Универсальный асинхронный веб-фаззер
│   └── vuln_scan.py      # Сканер базовых веб-уязвимостей
├── ad/
│   ├── ad_enum.py        # Скрипт для энумерации Active Directory
│   └── spray.py          # Модуль Password Spraying'а
├── post/
│   ├── pivot.sh          # Скрипт для настройки туннелей (pivoting)
│   └── loot.py           # Управление собранными артефактами
└── utils/
    ├── shell_upgrade.py  # Справочник команд для Reverse Shell
    └── encode.py         # Утилита для кодирования/декодирования
```

</details>

---

## ⚠️ Дисклеймер

> Данный инструментарий создан **ИСКЛЮЧИТЕЛЬНО** для авторизованного тестирования на проникновение, участия в CTF соревнованиях и в образовательных целях.
>
> Автор не несет ответственности за любой ущерб, причиненный в результате использования данного ПО. Использование против систем без явного письменного разрешения их владельцев является **незаконным**.

<div align="right">
  <b>GUTS @ Ynk4ts</b>
</div>