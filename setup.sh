#!/usr/bin/env bash
# =============================================================================
# R3KT — setup.sh
# Arch Linux | установка окружения + интерактивный лаунчер
#
# Использование:
#   ./setup.sh           — открыть лаунчер (меню)
#   ./setup.sh install   — полная установка всех инструментов
#   ./setup.sh check     — проверить зависимости
# =============================================================================

set -euo pipefail

# =============================================================================
# PATH — добавляем все пути при каждом запуске скрипта
# =============================================================================

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"
export PATH="$PATH:$HOME/.local/bin"
GEM_BIN=$(ruby -e 'puts Gem.user_dir' 2>/dev/null)/bin
[[ -d "$GEM_BIN" ]] && export PATH="$PATH:$GEM_BIN"
unset GEM_BIN

# =============================================================================
# Цвета
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

log()     { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; }
info()    { echo -e "${BLUE}[*]${NC} $*"; }
section() {
    echo -e "\n${CYAN}${BOLD}══════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $*${NC}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${NC}\n"
}

# =============================================================================
# Конфигурация
# =============================================================================

TOOLKIT_DIR="${TOOLKIT:-$HOME/r3kt}"
TOOLS_DIR="$HOME/.local/bin"
LOG_FILE="$TOOLKIT_DIR/setup.log"
VENV_PYTHON="$TOOLKIT_DIR/.venv/bin/python3"

cmd_exists() { command -v "$1" &>/dev/null; }
venv_ok()    { [[ -f "$VENV_PYTHON" ]]; }

get_python() {
    if venv_ok; then echo "$VENV_PYTHON"
    elif cmd_exists python3; then echo "python3"
    else echo "python"; fi
}

# =============================================================================
# ШАПКА
# =============================================================================

print_banner() {
    clear
    local variant=$(( RANDOM % 6 ))
    echo -e "${CYAN}${BOLD}"
    case $variant in
        0)
cat << 'BANNER'

  ██████╗ ██████╗ ██╗  ██╗████████╗
  ██╔══██╗╚════██╗██║ ██╔╝╚══██╔══╝
  ██████╔╝ █████╔╝█████╔╝    ██║   
  ██╔══██╗ ╚═══██╗██╔═██╗    ██║   
  ██║  ██║██████╔╝██║  ██╗   ██║   
  ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   

  ══════════════════════════════════════════════════
  ·  Recon & Exploitation Kit  ·  v1.0             ·
  ·  by GUTS @ Ynk4ts          ·  Standoff 365     ·
  ══════════════════════════════════════════════════

BANNER
        ;;
        1)
cat << 'BANNER'

  ▄████████  ▄█   ▄█▄     ███      
  ███    ███ ███  ▄███▀▀█  ███      
  ███    ███ ███▐▐██▀ ▄██▀ ███      
  ███    ███ █████▄  ▄██▀  ███      
  ███    ███ ███ ▀█▄▄██▀   ███      
  ███    ███ ███   ▀███     ███      
  ███    ███ ███    ███     ███▌    ▄
  ████████▀  █▀     ▀        █████▄█▀

  Recon & Exploitation Kit  ·  v1.0
  GUTS @ Ynk4ts  ·  Standoff 365

BANNER
        ;;
        2)
cat << 'BANNER'

  ╔══╗ ╔══╗ ╦╔═ ╔════╗
  ╠╦╝  ╚══╗ ╠╩╗    ╔╝ 
  ╩╚═  ╚══╝ ╩ ╩    ╩  

  ┌─────────────────────────────────────────────┐
  │  [*] Recon      [*] Web          [*] AD     │
  │  [*] Exploit    [*] Post         [*] Loot   │
  └─────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────┐
  │  by GUTS @ Ynk4ts           v1.0            │
  └─────────────────────────────────────────────┘

BANNER
        ;;
        3)
cat << 'BANNER'

   ____  ____  _  _  _____
  |  _ \|___ \| |/ /|_   _|
  | |_) | __) |    <  | |  
  |  _ < / __/| |\  \ | |  
  |_| \_\_____|_| \_/ |_|  

  ╔════════════════════════════════════════════╗
  ║  Recon & Exploitation Kit          v1.0    ║
  ║  ──────────────────────────────────────    ║
  ║  recon → osint → fuzz → enum → pwn → loot ║
  ║  ──────────────────────────────────────    ║
  ║  GUTS @ Ynk4ts              Standoff 365   ║
  ╚════════════════════════════════════════════╝

BANNER
        ;;
        4)
cat << 'BANNER'

         ::::::::: ::::::::::  :::    ::: :::::::::::
         :+:    :+::+:        :+:   :+:      :+:     
         +:+    +:++:+        +:+  +:+       +:+      
         +#++:++#: +#++:++#   +#++:++        +#+       
         +#+  +#+ +#+         +#+  +#+       +#+        
         #+#   #+##+#         #+#   #+#      #+#        
         ###    ########## ###     ### ###########     

  ══════════════════════════════════════════════════
   Recon & Exploitation Kit  ·  GUTS @ Ynk4ts
  ══════════════════════════════════════════════════

BANNER
        ;;
        5)
cat << 'BANNER'

⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿
⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿
⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿
⣿⣿⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣀⠀⠀⠀⠀⠀⣿⣿
⣿⣿⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⣿⣿
⣿⣿⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⢰⣿⣿
⣿⣿⣆⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⡇⠀⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠁⢸⣿⣿
⣿⣿⡇⠀⠀⠀⠘⣿⣿⣿⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⢿⣿⣿⡿⠀⠀⠀⢸⣿⣿
⣿⣿⡿⠿⠓⠂⠸⣿⠋⠀⢀⣠⣤⣾⣿⣿⣿⣦⣄⠀⠀⠀⠀⠀⠈⠛⠿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠁⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣶⣤⡀⠀⠈⣿⡇⠀⠚⠛⢻⣿⣿
⣿⣿⣇⡀⠀⠀⠀⢻⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣿⡇⣀⣀⣀⣸⣿⣿
⣿⣿⡿⠟⠛⠉⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⠀⠀⠀⢀⣾⣿⣿⣿⣄⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡈⠉⠙⢻⣿⣿
⣿⣿⣇⣠⣴⣾⣿⣿⣿⠋⣽⣿⣿⣿⣿⣿⡿⠿⠿⠟⠿⢿⣿⣿⣿⣶⣶⣿⣿⣿⣿⣿⣿⣷⣶⣾⣿⣿⣿⠿⠿⠟⠿⠿⢿⣿⣿⣿⣿⣯⡙⢿⣿⣿⣿⣷⣤⣸⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⡇⢰⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠁⠀⠀⠀⠀⠀⠀⠉⢻⣿⣿⣿⣧⠈⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣧⣼⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⢿⣿⣿⣿⢿⣿⣿⣟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣰⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⣀⣠⣤⣤⣤⣤⣄⣀⠀⢀⣴⣿⣿⣿⣿⢸⣿⣿⣿⡎⣿⣿⣿⣷⡄⠀⢀⣀⣤⣤⣤⣤⣤⣤⣙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣽⣿⣿⡿⢋⣾⣿⣿⣿⣧⡹⢿⣿⣋⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢋⣴⣿⣿⣿⣿⣿⣿⣿⣦⡙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⠟⠁⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠙⢿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⡟⠁⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠙⣿⣿⣿⣿⣿
⣿⣿⣿⣿⡟⠀⠀⠀⠀⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠛⠉⠉⠉⠉⠙⢿⣿⣿⣿⣿⣿⠟⠉⠁⠈⠉⠉⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠸⣿⣿⣿⣿
⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠙⠛⠿⠿⠿⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠛⠛⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠿⠿⠿⠛⠉⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿
⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿
⣿⣿⡿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⠿⣿⣿
⣿⣿⡇⠈⠻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⡿⠁⠀⣿⣿
⣿⣿⡇⠀⠀⠙⣷⣦⣤⣄⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣤⣴⣿⡟⠀⠀⠀⣿⣿
⣿⣿⡇⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡉⠉⠉⠀⠈⠉⠙⠛⠛⠷⠶⠶⠶⠶⠞⠛⠛⠉⠉⠉⠉⠉⢩⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⣿⣿
⣿⣿⡇⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⣿⣿
⣿⣿⡇⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⣿⣿
⣿⣿⡇⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣶⣤⣴⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀⣿⣿
⣿⣿⡇⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⣿⣿
⣿⣿⡇⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⣿⣿
⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⣿⣿
⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿
⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿
⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿
⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿
⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⠿⠛⠛⠛⠛⠿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣰⣶⣶⣶⣶⡆⢠⣴⣾⣷⣶⡄⠀⢀⣴⣾⣿⣶⣄⠀⠀⠀⣠⣶⣾⣷⡆⢰⣶⣶⡆⣴⣶⣶⣶⣶⣆⣶⣶⣶⣶⣶⣶⣶⣶⣆⢀⣶⣶⡶⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⡿⠿⠿⢁⣿⣿⡿⠻⣿⠁⣰⣿⣿⣿⣿⣿⣿⣆⠀⣼⣿⣿⣿⣿⡇⢸⣿⣿⠀⣿⣿⡿⠿⠿⢸⣿⣿⣿⣿⣿⡇⢿⣿⣿⣾⣿⡿⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣧⣤⡄⠘⣿⣿⣷⣤⡀⢠⣿⣿⡟⠀⠈⣿⣿⣿⢸⣿⣿⠏⠀⠀⠁⣾⣿⣿⢀⣿⣿⣷⣶⡆⠀⠀⣿⣿⡏⠀⠀⠘⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⠇⠀⠈⠛⣿⣿⣿⢸⣿⣿⡇⠀⢠⣿⣿⡏⢸⣿⣿⡀⠀⢀⠀⣿⣿⡇⢸⣿⣿⠿⠿⠇⠀⢰⣿⣿⡇⠀⠀⠀⣿⣿⣿⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣸⣿⣿⠀⠀⠀⣼⣷⣴⣿⣿⡿⠘⣿⣿⣿⣿⣿⣿⡟⠀⢸⣿⣿⣿⣿⡿⢸⣿⣿⡇⣼⣿⣿⣤⣤⡄⠀⢸⣿⣿⠁⠀⠀⠀⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⣿⡿⠀⠀⠘⠿⢿⣿⡿⠟⠁⠀⠘⠿⣿⣿⠿⠋⠀⠀⠀⠹⢿⣿⡿⠇⢸⣿⣿⠃⣿⣿⣿⣿⣿⠀⠀⣾⣿⣿⠀⠀⠀⢠⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀
  ──────────────────────────
  Recon & Exploitation Kit  
  ──────────────────────────
  ┌──────────────────────────────────────────┐
  │                                          │
  │   "Hack the planet"                      │
  │                  — GUTS @ Ynk4ts         │
  │                                          │
  └──────────────────────────────────────────┘
  v1.0  ·  Standoff 365  ·  CTF  ·  RedTeam

BANNER
        ;;
    esac
    echo -e "${NC}"
}

# =============================================================================
# ─── УСТАНОВКА ───────────────────────────────────────────────────────────────
# =============================================================================

check_not_root() {
    if [[ $EUID -eq 0 ]]; then
        error "Не запускай от root! Используй обычного пользователя с sudo."
        exit 1
    fi
}

install_if_missing() {
    local pkg="$1"
    if ! pacman -Qi "$pkg" &>/dev/null; then
        info "Устанавливаю $pkg..."
        sudo pacman -S --noconfirm "$pkg" >> "$LOG_FILE" 2>&1 \
            && log "$pkg установлен" \
            || warn "Не удалось: $pkg"
    else
        log "$pkg уже установлен"
    fi
}

aur_install() {
    local pkg="$1"
    if ! pacman -Qi "$pkg" &>/dev/null && cmd_exists yay; then
        info "AUR: $pkg..."
        yay -S --noconfirm "$pkg" >> "$LOG_FILE" 2>&1 \
            && log "$pkg (AUR) установлен" \
            || warn "Не удалось (AUR): $pkg"
    fi
}

pip_install() {
    local pkg="$1"
    info "pipx: $pkg..."
    pipx install "$pkg" >> "$LOG_FILE" 2>&1 \
        && log "$pkg установлен" \
        || warn "Не удалось: $pkg"
}

go_install() {
    local pkg="$1" name="$2"
    if ! cmd_exists "$name"; then
        info "go install: $name..."
        go install "$pkg" >> "$LOG_FILE" 2>&1 \
            && log "$name установлен" \
            || warn "Не удалось: $name"
    else
        log "$name уже установлен"
    fi
}

install_yay() {
    section "AUR Helper (yay)"
    if cmd_exists yay; then log "yay уже установлен"; return; fi
    local tmp; tmp=$(mktemp -d)
    git clone https://aur.archlinux.org/yay.git "$tmp/yay" >> "$LOG_FILE" 2>&1
    (cd "$tmp/yay" && makepkg -si --noconfirm) >> "$LOG_FILE" 2>&1
    rm -rf "$tmp"
    log "yay установлен"
}

install_system_deps() {
    section "Системные зависимости"
    sudo pacman -Syu --noconfirm >> "$LOG_FILE" 2>&1
    local pkgs=(
        base-devel git curl wget unzip tar
        nmap masscan netcat openbsd-netcat socat
        python python-pip python-pipx python-virtualenv
        ruby rubygems jq whois bind-tools ldns
        tmux fzf ripgrep bat fd openssl cmake gcc make
    )
    for pkg in "${pkgs[@]}"; do install_if_missing "$pkg"; done
}

install_go_runtime() {
    section "Go"
    if cmd_exists go; then log "Go уже установлен: $(go version)"; return; fi
    install_if_missing go
    grep -q 'GOPATH' "$HOME/.bashrc" 2>/dev/null || {
        echo 'export GOPATH=$HOME/go' >> "$HOME/.bashrc"
        echo 'export PATH=$PATH:$GOPATH/bin' >> "$HOME/.bashrc"
    }
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"
}

install_recon_tools() {
    section "Recon инструменты"
    go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "subfinder"
    go_install "github.com/projectdiscovery/httpx/cmd/httpx@latest"            "httpx"
    go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"       "nuclei"
    go_install "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"         "naabu"
    go_install "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"              "dnsx"
    go_install "github.com/projectdiscovery/katana/cmd/katana@latest"          "katana"
    go_install "github.com/lc/gau/v2/cmd/gau@latest"                           "gau"
    go_install "github.com/tomnomnom/waybackurls@latest"                        "waybackurls"
    go_install "github.com/tomnomnom/assetfinder@latest"                        "assetfinder"
    go_install "github.com/hakluke/hakrawler@latest"                            "hakrawler"
    go_install "github.com/tomnomnom/anew@latest"                               "anew"
    cmd_exists nuclei && nuclei -update-templates >> "$LOG_FILE" 2>&1 || true
    pip_install "theHarvester" || true
    pip_install "dnsrecon"     || true
}

install_web_tools() {
    section "Веб-инструменты"
    go_install "github.com/ffuf/ffuf/v2@latest"       "ffuf"
    go_install "github.com/OJ/gobuster/v3@latest"     "gobuster"
    go_install "github.com/hahwul/dalfox/v2@latest"   "dalfox"
    aur_install "feroxbuster"
    pip_install "sqlmap"  || true
    pip_install "arjun"   || true
    install_if_missing "nikto"
    if [[ ! -d "$TOOLKIT_DIR/tools/jwt_tool" ]]; then
        git clone https://github.com/ticarpi/jwt_tool \
            "$TOOLKIT_DIR/tools/jwt_tool" >> "$LOG_FILE" 2>&1
        ln -sf "$TOOLKIT_DIR/tools/jwt_tool/jwt_tool.py" "$TOOLS_DIR/jwt_tool"
        chmod +x "$TOOLKIT_DIR/tools/jwt_tool/jwt_tool.py"
        log "jwt_tool установлен"
    fi
}

install_ad_tools() {
    section "Active Directory инструменты"
    pip_install "impacket"       || true
    pip_install "bloodhound"     || true
    pip_install "certipy-ad"     || true
    pip_install "ldapdomaindump" || true
    pip_install "mitm6"          || true

    # netexec — ставим через BlackArch/AUR (в PyPI нет)
    if ! cmd_exists netexec && ! cmd_exists nxc; then
        info "netexec (через yay/BlackArch)..."
        if cmd_exists yay; then
            yay -S --noconfirm netexec >> "$LOG_FILE" 2>&1 \
                && log "netexec установлен через yay" \
                || warn "netexec: не удалось через yay"
        else
            warn "netexec: yay не найден, установи вручную: yay -S netexec"
        fi
    else
        log "netexec/nxc уже установлен"
    fi

    go_install "github.com/ropnop/kerbrute@latest" "kerbrute"

    # evil-winrm + фикс PATH для gem
    if ! cmd_exists evil-winrm; then
        gem install evil-winrm >> "$LOG_FILE" 2>&1 || true
        # Добавляем gem bin в PATH
        local gem_bin
        gem_bin=$(ruby -e 'puts Gem.user_dir' 2>/dev/null)/bin
        if [[ -d "$gem_bin" ]]; then
            grep -q "$gem_bin" "$HOME/.bashrc" 2>/dev/null || \
                echo "export PATH=\$PATH:$gem_bin" >> "$HOME/.bashrc"
            export PATH="$PATH:$gem_bin"
            log "gem PATH добавлен: $gem_bin"
        fi
    fi
    if [[ ! -d "$TOOLKIT_DIR/tools/enum4linux-ng" ]]; then
        git clone https://github.com/cddmp/enum4linux-ng \
            "$TOOLKIT_DIR/tools/enum4linux-ng" >> "$LOG_FILE" 2>&1
        ln -sf "$TOOLKIT_DIR/tools/enum4linux-ng/enum4linux-ng.py" \
            "$TOOLS_DIR/enum4linux-ng"
        chmod +x "$TOOLKIT_DIR/tools/enum4linux-ng/enum4linux-ng.py"
        log "enum4linux-ng установлен"
    fi
    if [[ ! -d "$TOOLKIT_DIR/tools/Responder" ]]; then
        git clone https://github.com/lgandx/Responder \
            "$TOOLKIT_DIR/tools/Responder" >> "$LOG_FILE" 2>&1
        log "Responder установлен"
    fi
}

install_post_tools() {
    section "Пост-эксплуатация и Pivoting"
    go_install "github.com/jpillora/chisel@latest" "chisel"

    if ! cmd_exists ligolo-proxy && [[ ! -f "$TOOLS_DIR/ligolo-proxy" ]]; then
        info "Скачиваю ligolo-ng..."
        local latest ver tmp url
        latest=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest \
            | grep '"tag_name"' | cut -d'"' -f4 2>/dev/null || echo "v0.6.2")
        ver="${latest#v}"
        url="https://github.com/nicocha30/ligolo-ng/releases/download/${latest}/ligolo-ng_proxy_${ver}_linux_amd64.tar.gz"
        tmp=$(mktemp -d)
        curl -sL "$url" -o "$tmp/proxy.tar.gz" >> "$LOG_FILE" 2>&1
        tar -xzf "$tmp/proxy.tar.gz" -C "$tmp" >> "$LOG_FILE" 2>&1
        find "$tmp" -name "proxy" -exec cp {} "$TOOLS_DIR/ligolo-proxy" \; 2>/dev/null || true
        chmod +x "$TOOLS_DIR/ligolo-proxy" 2>/dev/null || true
        rm -rf "$tmp"
        log "ligolo-proxy установлен"
    fi

    pip_install "pwncat-cs" || true

    if [[ ! -f "$TOOLKIT_DIR/post/linpeas.sh" ]]; then
        info "Скачиваю PEASS-ng..."
        curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh \
            -o "$TOOLKIT_DIR/post/linpeas.sh" >> "$LOG_FILE" 2>&1
        curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe \
            -o "$TOOLKIT_DIR/post/winPEASx64.exe" >> "$LOG_FILE" 2>&1
        chmod +x "$TOOLKIT_DIR/post/linpeas.sh"
        log "PEASS-ng скачан"
    fi

    if [[ ! -f "$TOOLKIT_DIR/post/pspy64" ]]; then
        curl -sL https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 \
            -o "$TOOLKIT_DIR/post/pspy64" >> "$LOG_FILE" 2>&1
        chmod +x "$TOOLKIT_DIR/post/pspy64"
        log "pspy64 скачан"
    fi
}

install_wordlists() {
    section "Wordlists"
    local wl_dir="$TOOLKIT_DIR/wordlists"
    if [[ ! -d "$wl_dir/SecLists" ]]; then
        info "Клонирую SecLists (~1GB, может занять время)..."
        git clone --depth 1 https://github.com/danielmiessler/SecLists \
            "$wl_dir/SecLists" >> "$LOG_FILE" 2>&1
        log "SecLists установлен"
    else
        log "SecLists уже есть"
    fi

    if [[ ! -f "$wl_dir/rockyou.txt" ]]; then
        if   [[ -f /usr/share/wordlists/rockyou.txt ]]; then
            ln -sf /usr/share/wordlists/rockyou.txt "$wl_dir/rockyou.txt"
        elif [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
            gunzip -c /usr/share/wordlists/rockyou.txt.gz > "$wl_dir/rockyou.txt"
        else
            curl -sL \
                https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt \
                -o "$wl_dir/rockyou.txt" >> "$LOG_FILE" 2>&1
        fi
        log "rockyou.txt готов"
    fi
}

setup_python_env() {
    section "Python окружение (venv)"
    [[ ! -d "$TOOLKIT_DIR/.venv" ]] && {
        python -m venv "$TOOLKIT_DIR/.venv"
        log "venv создан"
    }
    source "$TOOLKIT_DIR/.venv/bin/activate"
    pip install --upgrade pip >> "$LOG_FILE" 2>&1
    local pkgs=(
        requests httpx aiohttp beautifulsoup4 lxml
        dnspython python-whois colorama rich typer
        pydantic paramiko impacket ldap3 python-nmap shodan
    )
    for pkg in "${pkgs[@]}"; do
        pip install "$pkg" >> "$LOG_FILE" 2>&1 \
            && log "pip: $pkg" \
            || warn "pip: $pkg не установлен"
    done
    deactivate
}

setup_aliases() {
    section "Алиасы"
    local alias_file="$TOOLKIT_DIR/aliases.sh"
    cat > "$alias_file" << ALIASES
# R3KT — алиасы
export TOOLKIT="$HOME/r3kt"
export WORDLISTS="\$TOOLKIT/wordlists"
export SECLISTS="\$WORDLISTS/SecLists"
export LOOT="\$TOOLKIT/loot"

# Быстрый запуск лаунчера
alias standoff='\$TOOLKIT/setup.sh'
alias st='\$TOOLKIT/setup.sh'

# Утилиты
alias serve='python3 -m http.server 8080'
alias myip='curl -s ifconfig.me'
alias tun0ip="ip addr show tun0 2>/dev/null | grep 'inet ' | awk '{print \$2}' | cut -d/ -f1"

# Impacket shortcuts
alias secretsdump='impacket-secretsdump'
alias psexec='impacket-psexec'
alias wmiexec='impacket-wmiexec'
alias ntlmrelayx='impacket-ntlmrelayx'
alias getuserspns='impacket-GetUserSPNs'
alias getnpusers='impacket-GetNPUsers'

# hashcat shortcuts
alias hcntlm='hashcat -m 1000'
alias hcntlmv2='hashcat -m 5600'
alias hcasrep='hashcat -m 18200'
alias hckerb='hashcat -m 13100'
ALIASES

    grep -q "r3kt/aliases.sh" "$HOME/.bashrc" 2>/dev/null || {
        { echo ""; echo "# R3KT"; echo "source $alias_file"; } \
            >> "$HOME/.bashrc"
        log "Алиасы добавлены в .bashrc"
    }
    [[ -f "$HOME/.zshrc" ]] && grep -q "r3kt/aliases.sh" "$HOME/.zshrc" 2>/dev/null || {
        { echo ""; echo "# R3KT"; echo "source $alias_file"; } \
            >> "$HOME/.zshrc" 2>/dev/null || true
        log "Алиасы добавлены в .zshrc"
    }
    grep -q "$TOOLS_DIR" "$HOME/.bashrc" 2>/dev/null || \
        echo "export PATH=\$PATH:$TOOLS_DIR" >> "$HOME/.bashrc"
}

setup_tmux() {
    [[ -f "$HOME/.tmux.conf" ]] && { log "tmux конфиг уже есть"; return; }
    cat > "$HOME/.tmux.conf" << 'TMUX'
set -g default-terminal "screen-256color"
set -g history-limit 50000
set -g mouse on
unbind C-b
set-option -g prefix C-a
bind-key C-a send-prefix
bind | split-window -h -c "#{pane_current_path}"
bind - split-window -v -c "#{pane_current_path}"
bind -n M-Left  select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up    select-pane -U
bind -n M-Down  select-pane -D
set -g status-style bg=colour235,fg=colour255
set -g status-left  "#[fg=colour82,bold] ⚡ #S "
set -g status-right "#[fg=colour214] %H:%M  #[fg=colour82]%d/%m/%Y "
set -g window-status-current-style fg=colour214,bold
set -g base-index 1
setw -g pane-base-index 1
bind r source-file ~/.tmux.conf \; display "Reloaded!"
TMUX
    log "tmux конфиг создан"
}

run_full_install() {
    check_not_root
    mkdir -p "$TOOLKIT_DIR"/{recon,web,ad,post,utils,wordlists,loot,tools,sessions}
    touch "$LOG_FILE"
    print_banner
    echo -e "${YELLOW}${BOLD}  Запускается полная установка...${NC}\n"
    info "Лог: $LOG_FILE"
    sleep 1

    install_system_deps
    install_yay
    install_go_runtime
    install_recon_tools
    install_web_tools
    install_ad_tools
    install_post_tools
    install_wordlists
    setup_python_env
    setup_aliases
    setup_tmux

    # Фикс PATH — pipx, gem, .local/bin
    section "Финальная настройка PATH"
    info "pipx ensurepath..."
    pipx ensurepath >> "$LOG_FILE" 2>&1 || true

    local gem_bin
    gem_bin=$(ruby -e 'puts Gem.user_dir' 2>/dev/null)/bin
    if [[ -d "$gem_bin" ]] && ! grep -q "$gem_bin" "$HOME/.bashrc" 2>/dev/null; then
        echo "export PATH=\\/home/claude/.npm-global/bin:/home/claude/.local/bin:/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$gem_bin" >> "$HOME/.bashrc"
        log "gem PATH добавлен: $gem_bin"
    fi

    grep -q '.local/bin' "$HOME/.bashrc" 2>/dev/null || \
        echo 'export PATH=$PATH:$HOME/.local/bin' >> "$HOME/.bashrc"

    section "✅ Установка завершена!"
    echo -e "${GREEN}${BOLD}  Все инструменты установлены!\n${NC}"
    echo -e "  ${YELLOW}${BOLD}Обязательно выполни:${NC}"
    echo -e "  ${BOLD}source ~/.bashrc${NC}\n"
    sleep 2
}

# =============================================================================
# ─── ЗАПУСК СКРИПТОВ ─────────────────────────────────────────────────────────
# =============================================================================

run_py() {
    local script="$1"; shift
    local py; py=$(get_python)
    if [[ ! -f "$script" ]]; then
        error "Файл не найден: $script"
        echo -e "${YELLOW}  Положи скрипт в: $script${NC}"
        echo -e "\n${DIM}  Enter для возврата...${NC}"; read -r; return
    fi
    echo ""
    "$py" "$script" "$@"
    echo -e "\n${DIM}  Enter для возврата в меню...${NC}"; read -r
}

run_sh() {
    local script="$1"; shift
    if [[ ! -f "$script" ]]; then
        error "Файл не найден: $script"
        echo -e "\n${DIM}  Enter для возврата...${NC}"; read -r; return
    fi
    chmod +x "$script"
    bash "$script" "$@"
    echo -e "\n${DIM}  Enter для возврата в меню...${NC}"; read -r
}

press_enter() {
    echo -e "\n${DIM}  Enter для возврата в меню...${NC}"; read -r
}

# =============================================================================
# ─── ПОДМЕНЮ ИНСТРУМЕНТОВ ────────────────────────────────────────────────────
# =============================================================================

menu_recon() {
    clear; print_banner
    section "🔍 recon.py — Автоматизация внешней разведки"
    echo -e "  ${DIM}Субдомены, порты, живые хосты, технологии, nuclei, dir fuzzing${NC}\n"

    echo -ne "  ${CYAN}Домен цели${NC} [например: company.ru]: "; read -r domain
    [[ -z "$domain" ]] && return

    echo -ne "  ${CYAN}Режим${NC} [fast/normal/full, default: normal]: "; read -r mode
    mode="${mode:-normal}"

    local args=("-d" "$domain")
    [[ "$mode" == "fast" ]] && args+=("--fast")
    [[ "$mode" == "full" ]] && args+=("--full")

    echo -ne "  ${CYAN}Пропустить nuclei?${NC} [y/N]: "; read -r skip_n
    [[ "${skip_n,,}" == "y" ]] && args+=("--skip-nuclei")

    run_py "$TOOLKIT_DIR/recon/recon.py" "${args[@]}"
}

menu_osint() {
    clear; print_banner
    section "🕵️  osint.py — Пассивная OSINT разведка"
    echo -e "  ${DIM}WHOIS/RDAP, DNS, ASN/IP, emails, GitHub/GitLab, Wayback, утечки, стек${NC}\n"

    echo -ne "  ${CYAN}Домен цели${NC} [например: company.ru]: "; read -r domain
    [[ -z "$domain" ]] && return

    echo -ne "  ${CYAN}Название компании${NC} (для HH.ru/GitHub, Enter=пропустить): "; read -r company

    local args=("-d" "$domain")
    [[ -n "$company" ]] && args+=("-c" "$company")

    echo -ne "  ${CYAN}Пропустить Wayback Machine?${NC} [y/N]: "; read -r skip_wb
    [[ "${skip_wb,,}" == "y" ]] && args+=("--skip-wayback")

    run_py "$TOOLKIT_DIR/recon/osint.py" "${args[@]}"
}

menu_fuzzer() {
    clear; print_banner
    section "🌐 fuzzer.py — Веб-фаззер"
    echo -e "  ${DIM}Директории, параметры, виртуальные хосты, FUZZ placeholder${NC}\n"

    echo -e "  Выбери режим:"
    echo -e "   ${CYAN}[1]${NC} dir    — Перебор директорий и файлов"
    echo -e "   ${CYAN}[2]${NC} params — Поиск скрытых параметров"
    echo -e "   ${CYAN}[3]${NC} vhost  — Virtual host fuzzing"
    echo -e "   ${CYAN}[4]${NC} fuzz   — Универсальный (FUZZ placeholder в URL)"
    echo -e "   ${CYAN}[5]${NC} ext    — Перебор расширений файла"
    echo ""
    echo -ne "  Выбор [1-5, default: 1]: "; read -r choice

    local modes=([1]="dir" [2]="params" [3]="vhost" [4]="fuzz" [5]="ext")
    local mode="${modes[${choice:-1}]:-dir}"

    echo -ne "  ${CYAN}URL цели${NC} [https://target.com]: "; read -r url
    [[ -z "$url" ]] && return

    local args=("$mode" "-u" "$url")

    if [[ "$mode" == "ext" ]]; then
        echo -ne "  ${CYAN}Базовое имя файла${NC} [backup]: "; read -r path
        args+=("--path" "${path:-backup}")
    elif [[ "$mode" == "dir" ]]; then
        echo -ne "  ${CYAN}Расширения${NC} [php,bak,old, Enter=пропустить]: "; read -r exts
        [[ -n "$exts" ]] && args+=("-x" "$exts")
    fi

    echo -ne "  ${CYAN}Прокси${NC} [http://127.0.0.1:8080, Enter=пропустить]: "; read -r proxy
    [[ -n "$proxy" ]] && args+=("--proxy" "$proxy")

    run_py "$TOOLKIT_DIR/web/fuzzer.py" "${args[@]}"
}

menu_vulnscan() {
    clear; print_banner
    section "🔎 vuln_scan.py — Сканер веб-уязвимостей"
    echo -e "  ${DIM}Заголовки безопасности, утечки файлов, CMS, SSL, директории, контент${NC}\n"

    echo -ne "  ${CYAN}URL цели${NC} [https://target.com]: "; read -r url
    [[ -z "$url" ]] && return

    echo -ne "  ${CYAN}Полный режим?${NC} (+ open redirect + auth checks) [y/N]: "; read -r full
    echo -ne "  ${CYAN}Cookies${NC} [session=abc; token=xyz, Enter=пропустить]: "; read -r cookies
    echo -ne "  ${CYAN}Прокси${NC} [http://127.0.0.1:8080, Enter=пропустить]: "; read -r proxy

    local args=("-u" "$url")
    [[ "${full,,}" == "y" ]] && args+=("--full")
    [[ -n "$cookies" ]] && args+=("--cookies" "$cookies")
    [[ -n "$proxy" ]]   && args+=("--proxy" "$proxy")

    run_py "$TOOLKIT_DIR/web/vuln_scan.py" "${args[@]}"
}

menu_adenum() {
    clear; print_banner
    section "🏢 ad_enum.py — Перечисление Active Directory"
    echo -e "  ${DIM}Пользователи, группы, SPNs, ACL, BloodHound, уязвимости (Zerologon, PrintNightmare...)${NC}\n"

    echo -ne "  ${CYAN}Домен${NC} [corp.local]: "; read -r domain
    [[ -z "$domain" ]] && return
    echo -ne "  ${CYAN}IP Domain Controller${NC}: "; read -r dc
    [[ -z "$dc" ]] && return
    echo -ne "  ${CYAN}Username${NC}: "; read -r user
    [[ -z "$user" ]] && return

    local args=("-d" "$domain" "--dc" "$dc" "-u" "$user")

    echo -ne "  ${CYAN}Password${NC} (Enter → хеш): "; read -rs password; echo ""
    if [[ -n "$password" ]]; then
        args+=("-p" "$password")
    else
        echo -ne "  ${CYAN}NTLM Hash${NC} [aad3b435:31d6c... или просто NT]: "; read -r hash
        [[ -z "$hash" ]] && return
        args+=("-H" "$hash")
    fi

    echo -e "\n  Режим:"
    echo -e "   ${CYAN}[1]${NC} normal      — стандартное перечисление"
    echo -e "   ${CYAN}[2]${NC} full        — + BloodHound + local admin sweep"
    echo -e "   ${CYAN}[3]${NC} only-users  — только пользователи + AS-REP/Kerberoast"
    echo -e "   ${CYAN}[4]${NC} only-vulns  — только уязвимости"
    echo ""
    echo -ne "  Выбор [1-4, default: 1]: "; read -r mode_choice

    case "${mode_choice:-1}" in
        2) args+=("--full") ;;
        3) args+=("--only-users") ;;
        4) args+=("--only-vulns") ;;
    esac

    run_py "$TOOLKIT_DIR/ad/ad_enum.py" "${args[@]}"
}

menu_spray() {
    clear; print_banner
    section "💦 spray.py — Password Spraying"
    echo -e "  ${DIM}Умный spray с защитой от локаута, 4 протокола, генератор паролей${NC}\n"

    echo -ne "  ${CYAN}Домен${NC} [corp.local]: "; read -r domain
    [[ -z "$domain" ]] && return
    echo -ne "  ${CYAN}IP Domain Controller${NC}: "; read -r dc
    [[ -z "$dc" ]] && return
    echo -ne "  ${CYAN}Файл с пользователями${NC}: "; read -r users_file
    [[ -z "$users_file" || ! -f "$users_file" ]] && {
        error "Файл не найден: $users_file"; press_enter; return
    }

    local args=("-d" "$domain" "--dc" "$dc" "-U" "$users_file")

    echo -e "\n  Пароли:"
    echo -e "   ${CYAN}[1]${NC} Один пароль"
    echo -e "   ${CYAN}[2]${NC} Файл с паролями"
    echo -e "   ${CYAN}[3]${NC} Сгенерировать под компанию"
    echo -ne "  Выбор [1-3]: "; read -r pw_choice

    case "${pw_choice:-1}" in
        1)
            echo -ne "  ${CYAN}Пароль${NC}: "; read -rs pw; echo ""
            args+=("-p" "$pw")
            ;;
        2)
            echo -ne "  ${CYAN}Файл с паролями${NC}: "; read -r pwfile
            args+=("-P" "$pwfile")
            ;;
        3)
            echo -ne "  ${CYAN}Название компании${NC}: "; read -r company
            args+=("--gen-passwords" "-c" "$company")
            ;;
    esac

    echo -ne "  ${CYAN}Протокол${NC} [smb/ldap/kerberos/winrm, default: smb]: "; read -r proto
    [[ -n "$proto" ]] && args+=("--proto" "$proto")

    run_py "$TOOLKIT_DIR/ad/spray.py" "${args[@]}"
}

menu_pivot() {
    clear; print_banner
    section "🔌 pivot.sh — Туннели и пивотинг"
    echo -e "  ${DIM}Ligolo-ng (Layer 3), Chisel (HTTP), SSH туннели, Socat relay${NC}\n"

    echo -e "  Действия:"
    echo -e "   ${CYAN}[1]${NC}  ligolo          — запустить Ligolo-ng proxy"
    echo -e "   ${CYAN}[2]${NC}  ligolo-agent    — команды для агента на жертве"
    echo -e "   ${CYAN}[3]${NC}  chisel-server   — запустить Chisel сервер"
    echo -e "   ${CYAN}[4]${NC}  chisel-agent    — команды для клиента на жертве"
    echo -e "   ${CYAN}[5]${NC}  ssh-socks       — SSH SOCKS5 туннель"
    echo -e "   ${CYAN}[6]${NC}  proxychains     — настроить proxychains"
    echo -e "   ${CYAN}[7]${NC}  serve           — HTTP сервер для доставки агентов"
    echo -e "   ${CYAN}[8]${NC}  status          — активные туннели и маршруты"
    echo -e "   ${CYAN}[9]${NC}  cheatsheet      — шпаргалка по пивотингу"
    echo ""
    echo -ne "  Выбор [1-9]: "; read -r choice

    local cmds=([1]="ligolo" [2]="ligolo-agent" [3]="chisel-server"
                [4]="chisel-agent" [5]="ssh-socks" [6]="proxychains"
                [7]="serve" [8]="status" [9]="cheatsheet")
    local cmd="${cmds[${choice:-8}]:-status}"

    if [[ "$cmd" == "ssh-socks" ]]; then
        echo -ne "  ${CYAN}user@host${NC}: "; read -r target
        run_sh "$TOOLKIT_DIR/post/pivot.sh" "ssh-socks" "$target"
    else
        run_sh "$TOOLKIT_DIR/post/pivot.sh" "$cmd"
    fi
}

menu_loot() {
    clear; print_banner
    section "💰 loot.py — Управление находками"
    echo -e "  ${DIM}Кредентиалы, хеши, хосты, заметки, флаги, тикеты, отчёт${NC}\n"

    echo -e "  Действия:"
    echo -e "   ${CYAN}[1]${NC}  show all      — показать всё"
    echo -e "   ${CYAN}[2]${NC}  show creds    — только кредентиалы"
    echo -e "   ${CYAN}[3]${NC}  show hashes   — только хеши"
    echo -e "   ${CYAN}[4]${NC}  show hosts    — только хосты"
    echo -e "   ${CYAN}[5]${NC}  add cred      — добавить кредентиалы"
    echo -e "   ${CYAN}[6]${NC}  add hash      — добавить хеш"
    echo -e "   ${CYAN}[7]${NC}  add host      — добавить хост"
    echo -e "   ${CYAN}[8]${NC}  add note      — добавить заметку"
    echo -e "   ${CYAN}[9]${NC}  owned         — пометить хост как owned"
    echo -e "   ${CYAN}[10]${NC} search        — поиск по всем данным"
    echo -e "   ${CYAN}[11]${NC} import        — импорт из директории"
    echo -e "   ${CYAN}[12]${NC} hashcat       — экспорт хешей для hashcat"
    echo -e "   ${CYAN}[13]${NC} report        — генерация Markdown отчёта"
    echo ""
    echo -ne "  Выбор [1-13]: "; read -r choice

    case "${choice:-1}" in
        1)  run_py "$TOOLKIT_DIR/post/loot.py" show all ;;
        2)  run_py "$TOOLKIT_DIR/post/loot.py" show creds ;;
        3)  run_py "$TOOLKIT_DIR/post/loot.py" show hashes ;;
        4)  run_py "$TOOLKIT_DIR/post/loot.py" show hosts ;;
        5)
            echo -ne "  User: "; read -r u
            echo -ne "  Password: "; read -rs pw; echo ""
            echo -ne "  Domain: "; read -r d
            echo -ne "  Host IP: "; read -r h
            echo -ne "  Service [smb/ldap/http/...]: "; read -r s
            run_py "$TOOLKIT_DIR/post/loot.py" add cred \
                -u "$u" -p "$pw" -d "$d" -H "$h" -s "$s"
            ;;
        6)
            echo -ne "  User: "; read -r u
            echo -ne "  Hash [LM:NT или NT]: "; read -r hsh
            echo -ne "  Type [ntlm/asrep/kerberoast, default: ntlm]: "; read -r t
            echo -ne "  Domain: "; read -r d
            run_py "$TOOLKIT_DIR/post/loot.py" add hash \
                -u "$u" -H "$hsh" -t "${t:-ntlm}" -d "$d"
            ;;
        7)
            echo -ne "  IP: "; read -r ip
            echo -ne "  Hostname: "; read -r hn
            echo -ne "  OS [Windows Server 2019...]: "; read -r os
            echo -ne "  Role [dc/workstation/server/web]: "; read -r role
            run_py "$TOOLKIT_DIR/post/loot.py" add host \
                -i "$ip" --hostname "$hn" --os "$os" -r "$role"
            ;;
        8)
            echo -ne "  Заметка: "; read -r note
            echo -ne "  Категория [general/bloodhound/exploit/...]: "; read -r cat
            run_py "$TOOLKIT_DIR/post/loot.py" add note "$note" -c "${cat:-general}"
            ;;
        9)
            echo -ne "  IP или hostname: "; read -r host
            run_py "$TOOLKIT_DIR/post/loot.py" owned "$host"
            ;;
        10)
            echo -ne "  Поисковый запрос: "; read -r q
            run_py "$TOOLKIT_DIR/post/loot.py" search "$q"
            ;;
        11)
            echo -ne "  Директория с результатами: "; read -r dir
            run_py "$TOOLKIT_DIR/post/loot.py" import --dir "$dir"
            ;;
        12) run_py "$TOOLKIT_DIR/post/loot.py" hashcat ;;
        13) run_py "$TOOLKIT_DIR/post/loot.py" report ;;
    esac
}

menu_shell() {
    clear; print_banner
    section "🐚 shell_upgrade.py — Шпаргалка по шеллам"
    echo -e "  ${DIM}Reverse shells, TTY upgrade, передача файлов, первые команды${NC}\n"

    local my_ip
    my_ip=$(ip addr show tun0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || \
            ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || \
            ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1 || ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -1 || echo "ATTACKER_IP")

    echo -ne "  ${CYAN}Твой IP${NC} [default: $my_ip]: "; read -r ip_input
    local ip="${ip_input:-$my_ip}"
    echo -ne "  ${CYAN}Порт${NC} [default: 4444]: "; read -r port_input
    local port="${port_input:-4444}"

    echo -e "\n  Что показать?"
    echo -e "   ${CYAN}[1]${NC} revshell — Reverse shell команды (bash/python/php/nc/ps...)"
    echo -e "   ${CYAN}[2]${NC} upgrade  — TTY Upgrade шаг за шагом"
    echo -e "   ${CYAN}[3]${NC} transfer — Передача файлов на жертву / exfiltration"
    echo -e "   ${CYAN}[4]${NC} post     — Первые команды после шелла"
    echo -e "   ${CYAN}[5]${NC} all      — Всё сразу"
    echo ""
    echo -ne "  Выбор [1-5, default: 5]: "; read -r choice

    local modes=([1]="revshell" [2]="upgrade" [3]="transfer" [4]="post" [5]="all")
    local mode="${modes[${choice:-5}]:-all}"

    run_py "$TOOLKIT_DIR/utils/shell_upgrade.py" "$mode" -i "$ip" -p "$port"
}

menu_encode() {
    clear; print_banner
    section "🔐 encode.py — Кодирование / декодирование"
    echo -e "  ${DIM}base64, url, hex, html, unicode, rot13, hash, jwt, powershell, gzip${NC}\n"

    echo -e "  Режимы:"
    echo -e "   ${CYAN}[1]${NC}  base64     — Base64 encode/decode"
    echo -e "   ${CYAN}[2]${NC}  url        — URL encode/decode (+ double/full/unicode)"
    echo -e "   ${CYAN}[3]${NC}  hex        — Hex encode/decode"
    echo -e "   ${CYAN}[4]${NC}  html       — HTML entities encode/decode"
    echo -e "   ${CYAN}[5]${NC}  unicode    — Unicode \\uXXXX escape"
    echo -e "   ${CYAN}[6]${NC}  rot13      — ROT13"
    echo -e "   ${CYAN}[7]${NC}  gzip       — Gzip + Base64"
    echo -e "   ${CYAN}[8]${NC}  powershell — PowerShell -EncodedCommand"
    echo -e "   ${CYAN}[9]${NC}  hash       — MD5/SHA1/SHA256/SHA512/NTLM"
    echo -e "   ${CYAN}[10]${NC} jwt        — JWT decode + анализ"
    echo -e "   ${CYAN}[11]${NC} all        — Все кодировки сразу"
    echo -e "   ${CYAN}[12]${NC} identify   — Автоопределение типа кодирования"
    echo ""
    echo -ne "  Выбор [1-12]: "; read -r choice

    local enc_map=([1]="base64" [2]="url" [3]="hex" [4]="html"
                   [5]="unicode" [6]="rot13" [7]="gzip" [8]="powershell"
                   [9]="hash" [10]="jwt" [11]="all" [12]="identify")
    local enc="${enc_map[${choice:-11}]:-all}"

    # JWT — только decode
    if [[ "$enc" == "jwt" ]]; then
        echo -ne "  ${CYAN}JWT токен${NC}: "; read -r data
        run_py "$TOOLKIT_DIR/utils/encode.py" jwt decode "$data"
        return
    fi

    # Identify — только данные
    if [[ "$enc" == "identify" ]]; then
        echo -ne "  ${CYAN}Данные для анализа${NC}: "; read -r data
        run_py "$TOOLKIT_DIR/utils/encode.py" identify "$data"
        return
    fi

    # Hash — спрашиваем алгоритм
    if [[ "$enc" == "hash" ]]; then
        echo -ne "  ${CYAN}Алгоритм${NC} [md5/sha1/sha256/sha512/ntlm/all, default: all]: "; read -r algo
        echo -ne "  ${CYAN}Данные${NC}: "; read -r data
        run_py "$TOOLKIT_DIR/utils/encode.py" hash "${algo:-all}" "$data"
        return
    fi

    # Остальные — encode или decode
    echo -ne "  ${CYAN}Операция${NC} [encode/decode, default: encode]: "; read -r op
    echo -ne "  ${CYAN}Данные${NC}: "; read -r data
    run_py "$TOOLKIT_DIR/utils/encode.py" "$enc" "${op:-encode}" "$data"
}

# =============================================================================
# ─── СЕРВИСНЫЕ ФУНКЦИИ ────────────────────────────────────────────────────────
# =============================================================================

fix_path() {
    section "Настройка PATH"

    local bashrc="$HOME/.bashrc"
    local zshrc="$HOME/.zshrc"
    local added=0

    # Go
    if ! grep -q 'GOPATH' "$bashrc" 2>/dev/null; then
        echo '' >> "$bashrc"
        echo '# Go' >> "$bashrc"
        echo 'export GOPATH=$HOME/go' >> "$bashrc"
        echo 'export PATH=$PATH:$GOPATH/bin' >> "$bashrc"
        log "Go PATH добавлен в .bashrc"
        ((added++))
    else
        log "Go PATH уже есть в .bashrc"
    fi

    # pipx / .local/bin
    if ! grep -q '\.local/bin' "$bashrc" 2>/dev/null; then
        echo 'export PATH=$PATH:$HOME/.local/bin' >> "$bashrc"
        log ".local/bin добавлен в .bashrc"
        ((added++))
    else
        log ".local/bin уже есть в .bashrc"
    fi

    # gem / ruby
    local gem_bin
    gem_bin=$(ruby -e 'puts Gem.user_dir' 2>/dev/null)/bin
    if [[ -d "$gem_bin" ]] && ! grep -q "$gem_bin" "$bashrc" 2>/dev/null; then
        echo "export PATH=\$PATH:$gem_bin" >> "$bashrc"
        log "gem PATH добавлен: $gem_bin"
        ((added++))
    else
        log "gem PATH уже настроен"
    fi

    # pipx ensurepath
    info "pipx ensurepath..."
    pipx ensurepath >> "$LOG_FILE" 2>&1 || true

    # Применяем в текущей сессии
    export GOPATH="$HOME/go"
    export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"
    [[ -d "$gem_bin" ]] && export PATH="$PATH:$gem_bin"

    # Дублируем в .zshrc если есть
    if [[ -f "$zshrc" ]]; then
        grep -q 'GOPATH' "$zshrc" 2>/dev/null || {
            echo 'export GOPATH=$HOME/go' >> "$zshrc"
            echo 'export PATH=$PATH:$GOPATH/bin:$HOME/.local/bin' >> "$zshrc"
            log "PATH добавлен в .zshrc"
        }
    fi

    echo ""
    log "PATH обновлён!"
    echo -e "
  ${YELLOW}Применить в текущем терминале:${NC}"
    echo -e "  ${BOLD}source ~/.bashrc${NC}"
    echo ""

    # Показываем что теперь доступно
    echo -e "  ${CYAN}Доступные инструменты:${NC}"
    local tools=(subfinder httpx nuclei ffuf gobuster dalfox
                 kerbrute chisel bloodhound-python certipy
                 evil-winrm netexec nxc)
    for t in "${tools[@]}"; do
        if cmd_exists "$t"; then
            echo -e "  ${GREEN}[+]${NC} $t → $(which "$t")"
        fi
    done

    press_enter
}

check_all_deps() {
    clear; print_banner
    section "Проверка зависимостей"

    local tools=(
        subfinder assetfinder httpx nuclei naabu dnsx katana gau waybackurls anew
        ffuf gobuster dalfox
        kerbrute chisel
        nmap socat tmux git curl wget jq
        evil-winrm
    )

    local ok=0 miss=0
    for t in "${tools[@]}"; do
        if cmd_exists "$t"; then
            echo -e "  ${GREEN}[+]${NC} $t"
            ((ok++))
        else
            echo -e "  ${RED}[-]${NC} $t"
            ((miss++))
        fi
    done

    echo ""
    echo -e "  ${GREEN}Найдено: $ok${NC}  |  ${RED}Отсутствует: $miss${NC}"
    echo ""
    echo -e "  Python скрипты:"
    local scripts=(
        "recon/recon.py" "recon/osint.py"
        "web/fuzzer.py" "web/vuln_scan.py"
        "ad/ad_enum.py" "ad/spray.py"
        "post/pivot.sh" "post/loot.py"
        "utils/shell_upgrade.py" "utils/encode.py"
    )
    for s in "${scripts[@]}"; do
        local full="$TOOLKIT_DIR/$s"
        if [[ -f "$full" ]]; then
            echo -e "  ${GREEN}[+]${NC} $s"
        else
            echo -e "  ${RED}[-]${NC} $s — не найден"
        fi
    done

    if [[ $miss -gt 0 ]]; then
        echo ""
        echo -ne "  ${YELLOW}Запустить установку?${NC} [y/N]: "; read -r ans
        [[ "${ans,,}" == "y" ]] && run_full_install
    fi

    press_enter
}

new_target_wizard() {
    clear; print_banner
    section "🎯 Новая цель"

    echo -ne "  ${CYAN}Название${NC} [company_bank]: "; read -r name
    [[ -z "$name" ]] && return
    echo -ne "  ${CYAN}IP / диапазон${NC} (Enter=пропустить): "; read -r scope

    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local work_dir="$TOOLKIT_DIR/loot/${name}_${ts}"
    mkdir -p "$work_dir"/{recon,web,ad,screenshots,loot,notes}

    cat > "$work_dir/notes/target.md" << MD
# Target: $name
**Date:** $(date)
**Scope:** $scope

## Credentials
| Username | Password/Hash | Service | Host |
|----------|--------------|---------|------|

## Findings
| # | Severity | Title | URL/Host |
|---|----------|-------|----------|

## Timeline
- $(date): initialized
MD

    log "Создана директория: $work_dir"
    echo ""

    if cmd_exists tmux && [[ -z "${TMUX:-}" ]]; then
        echo -ne "  ${CYAN}Запустить tmux сессию?${NC} [Y/n]: "; read -r ans
        if [[ "${ans,,}" != "n" ]]; then
            tmux new-session -d -s "$name" -c "$work_dir"
            tmux split-window -h  -t "$name"
            tmux split-window -v  -t "$name:0.1"
            tmux select-pane  -t  "$name:0.0"
            tmux send-keys -t "$name:0.0" \
                "echo '=== RECON ===' && cd $work_dir && cat notes/target.md" Enter
            tmux send-keys -t "$name:0.1" \
                "echo '=== ATTACK ===' && cd $work_dir" Enter
            tmux send-keys -t "$name:0.2" \
                "echo '=== LOOT ===' && cd $work_dir" Enter
            log "tmux сессия '$name' запущена"
            sleep 1
            tmux attach-session -t "$name"
            return
        fi
    fi
    press_enter
}

# =============================================================================
# ─── ГЛАВНОЕ МЕНЮ ─────────────────────────────────────────────────────────────
# =============================================================================

script_mark() {
    [[ -f "$1" ]] && echo -e "${GREEN}●${NC}" || echo -e "${RED}○${NC}"
}

show_main_menu() {
    clear
    print_banner

    local py; py=$(get_python)
    echo -e "  ${DIM}Python: $py${NC}"
    echo -e "  ${DIM}Toolkit: $TOOLKIT_DIR${NC}\n"

    echo -e "  ${BOLD}${MAGENTA}── 🔍 РАЗВЕДКА ──────────────────────────────────────${NC}"
    echo -e "  $(script_mark "$TOOLKIT_DIR/recon/recon.py") ${BOLD}${CYAN}[ 1]${NC}  ${BOLD}recon.py${NC}"
    echo -e "       ${DIM}Субдомены, порты, технологии, nuclei, directory fuzzing${NC}"
    echo -e "  $(script_mark "$TOOLKIT_DIR/recon/osint.py") ${BOLD}${CYAN}[ 2]${NC}  ${BOLD}osint.py${NC}"
    echo -e "       ${DIM}WHOIS, DNS, ASN, emails, GitHub, Wayback Machine, утечки${NC}"

    echo -e "\n  ${BOLD}${MAGENTA}── 🌐 ВЕБ ───────────────────────────────────────────${NC}"
    echo -e "  $(script_mark "$TOOLKIT_DIR/web/fuzzer.py") ${BOLD}${CYAN}[ 3]${NC}  ${BOLD}fuzzer.py${NC}"
    echo -e "       ${DIM}Dir/file/param/vhost fuzzing, FUZZ placeholder, ext scan${NC}"
    echo -e "  $(script_mark "$TOOLKIT_DIR/web/vuln_scan.py") ${BOLD}${CYAN}[ 4]${NC}  ${BOLD}vuln_scan.py${NC}"
    echo -e "       ${DIM}Security headers, утечки файлов, CMS, SSL, open redirect${NC}"

    echo -e "\n  ${BOLD}${MAGENTA}── 🏢 ACTIVE DIRECTORY ──────────────────────────────${NC}"
    echo -e "  $(script_mark "$TOOLKIT_DIR/ad/ad_enum.py") ${BOLD}${CYAN}[ 5]${NC}  ${BOLD}ad_enum.py${NC}"
    echo -e "       ${DIM}Users/groups/SPNs/ACL, AS-REP/Kerberoast, BloodHound, CVEs${NC}"
    echo -e "  $(script_mark "$TOOLKIT_DIR/ad/spray.py") ${BOLD}${CYAN}[ 6]${NC}  ${BOLD}spray.py${NC}"
    echo -e "       ${DIM}Password spraying с защитой от локаута, генератор паролей${NC}"

    echo -e "\n  ${BOLD}${MAGENTA}── 🔑 ПОСТ-ЭКСПЛУАТАЦИЯ ─────────────────────────────${NC}"
    echo -e "  $(script_mark "$TOOLKIT_DIR/post/pivot.sh") ${BOLD}${CYAN}[ 7]${NC}  ${BOLD}pivot.sh${NC}"
    echo -e "       ${DIM}Ligolo-ng, Chisel, SSH туннели, Socat relay, proxychains${NC}"
    echo -e "  $(script_mark "$TOOLKIT_DIR/post/loot.py") ${BOLD}${CYAN}[ 8]${NC}  ${BOLD}loot.py${NC}"
    echo -e "       ${DIM}Кредентиалы, хеши, хосты, заметки, импорт, отчёт${NC}"

    echo -e "\n  ${BOLD}${MAGENTA}── 🛠️  УТИЛИТЫ ──────────────────────────────────────${NC}"
    echo -e "  $(script_mark "$TOOLKIT_DIR/utils/shell_upgrade.py") ${BOLD}${CYAN}[ 9]${NC}  ${BOLD}shell_upgrade.py${NC}"
    echo -e "       ${DIM}Reverse shells, TTY upgrade, передача файлов, post-shell${NC}"
    echo -e "  $(script_mark "$TOOLKIT_DIR/utils/encode.py") ${BOLD}${CYAN}[10]${NC}  ${BOLD}encode.py${NC}"
    echo -e "       ${DIM}base64/url/hex/html/unicode/hash/jwt/powershell/identify${NC}"

    echo -e "\n  ${BOLD}${MAGENTA}── ⚙️  СИСТЕМА ───────────────────────────────────────${NC}"
    echo -e "  ${DIM}●${NC} ${BOLD}${CYAN}[ i]${NC}  ${BOLD}install${NC}    ${DIM}— Установить все инструменты${NC}"
    echo -e "  ${DIM}●${NC} ${BOLD}${CYAN}[ c]${NC}  ${BOLD}check${NC}      ${DIM}— Проверить зависимости${NC}"
    echo -e "  ${DIM}●${NC} ${BOLD}${CYAN}[ t]${NC}  ${BOLD}new-target${NC} ${DIM}— Создать директорию для новой цели${NC}"
    echo -e "  ${DIM}●${NC} ${BOLD}${CYAN}[ p]${NC}  ${BOLD}fix-path${NC}   ${DIM}— Починить PATH (если инструменты не видны)${NC}"
    echo -e "  ${DIM}●${NC} ${BOLD}${CYAN}[ q]${NC}  ${BOLD}quit${NC}       ${DIM}— Выход${NC}"

    echo ""
    echo -e "  ${GREEN}●${NC} скрипт найден   ${RED}○${NC} скрипт не найден"
    echo ""
    echo -ne "  ${BOLD}Введи номер:${NC} "
}

# =============================================================================
# MAIN LOOP
# =============================================================================

main_loop() {
    while true; do
        show_main_menu
        read -r choice

        case "${choice,,}" in
            1)         menu_recon    ;;
            2)         menu_osint    ;;
            3)         menu_fuzzer   ;;
            4)         menu_vulnscan ;;
            5)         menu_adenum   ;;
            6)         menu_spray    ;;
            7)         menu_pivot    ;;
            8)         menu_loot     ;;
            9)         menu_shell    ;;
            10)        menu_encode   ;;
            i|install) run_full_install; sleep 1 ;;
            c|check)   check_all_deps ;;
            p|fix-path|path) fix_path ;;
            t|target)  new_target_wizard ;;
            q|quit|exit|"")
                echo -e "\n${CYAN}  Удачи на R3KT! ⚡${NC}\n"
                exit 0
                ;;
            *)
                echo -e "  ${RED}Неверный выбор: $choice${NC}"
                sleep 1
                ;;
        esac
    done
}

# =============================================================================
# ENTRY POINT
# =============================================================================

main() {
    mkdir -p "$TOOLKIT_DIR"/{recon,web,ad,post,utils,wordlists,loot,tools,sessions}
    touch "$LOG_FILE" 2>/dev/null || true

    case "${1:-menu}" in
        install|setup)
            check_not_root
            run_full_install
            main_loop
            ;;
        menu|"")
            # Первый запуск — предлагаем установку
            if ! cmd_exists subfinder && ! cmd_exists httpx && ! cmd_exists nmap; then
                print_banner
                warn "Инструменты не установлены!"
                echo -ne "  ${CYAN}Запустить установку сейчас?${NC} [Y/n]: "; read -r ans
                [[ "${ans,,}" != "n" ]] && { check_not_root; run_full_install; }
            fi
            main_loop
            ;;
        check)
            check_all_deps
            ;;
        *)
            echo "Использование: $0 [install|menu|check]"
            echo ""
            echo "  (без аргументов) — открыть лаунчер"
            echo "  install          — полная установка"
            echo "  check            — проверить зависимости"
            ;;
    esac
}

main "$@"



















