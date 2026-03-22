#!/usr/bin/env bash
# netdoc-setup.sh
# Instalator NetDoc dla Linux i macOS.
# Sprawdza wymagania, konfiguruje środowisko i uruchamia system.
#
# Użycie:
#   chmod +x netdoc-setup.sh
#   ./netdoc-setup.sh

set -euo pipefail

# ── Kolory ────────────────────────────────────────────────────────────────────

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
GRAY='\033[0;90m'
NC='\033[0m'

step()  { echo -e "\n${CYAN}  >> $*${NC}"; }
ok()    { echo -e "${GREEN}     [OK] $*${NC}"; }
warn()  { echo -e "${YELLOW}     [!!] $*${NC}"; }
fail()  { echo -e "${RED}     [BLAD] $*${NC}"; }
info()  { echo -e "${GRAY}           $*${NC}"; }

# ── Wykrywanie OS i package managera ──────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS="unknown"
PKG_MANAGER="none"

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ -f /etc/os-release ]]; then
        source /etc/os-release 2>/dev/null
        OS="linux"
        if command -v apt-get &>/dev/null; then
            PKG_MANAGER="apt"
        elif command -v dnf &>/dev/null; then
            PKG_MANAGER="dnf"
        elif command -v yum &>/dev/null; then
            PKG_MANAGER="yum"
        elif command -v pacman &>/dev/null; then
            PKG_MANAGER="pacman"
        elif command -v zypper &>/dev/null; then
            PKG_MANAGER="zypper"
        fi
    fi
}

# ── Nagłówek ──────────────────────────────────────────────────────────────────

clear
echo -e "${CYAN}"
echo "  ================================================"
echo "   NetDoc  —  Instalator Linux / macOS"
echo "  ================================================"
echo -e "${NC}"
echo -e "${GRAY}  Katalog projektu: $SCRIPT_DIR${NC}"

detect_os

echo -e "${GRAY}  System:          $OS${NC}"
[[ "$OS" == "linux" ]] && echo -e "${GRAY}  Package manager: $PKG_MANAGER${NC}"
echo ""

# ── Funkcja instalacji pakietu ────────────────────────────────────────────────

install_pkg() {
    local pkg_linux="$1"
    local pkg_brew="$2"
    local label="$3"

    warn "$label nie znaleziony — próbuję zainstalować..."

    if [[ "$OS" == "macos" ]]; then
        if command -v brew &>/dev/null; then
            brew install "$pkg_brew" || { fail "Instalacja $label przez Homebrew nie powiodła się."; return 1; }
        else
            fail "Homebrew nie jest zainstalowany. Zainstaluj ze strony https://brew.sh"
            info "Następnie uruchom: brew install $pkg_brew"
            return 1
        fi
    elif [[ "$PKG_MANAGER" == "apt" ]]; then
        sudo apt-get update -qq && sudo apt-get install -y "$pkg_linux" || { fail "apt install $pkg_linux nie powiodło się."; return 1; }
    elif [[ "$PKG_MANAGER" == "dnf" ]]; then
        sudo dnf install -y "$pkg_linux" || { fail "dnf install $pkg_linux nie powiodło się."; return 1; }
    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        sudo yum install -y "$pkg_linux" || { fail "yum install $pkg_linux nie powiodło się."; return 1; }
    elif [[ "$PKG_MANAGER" == "pacman" ]]; then
        sudo pacman -S --noconfirm "$pkg_linux" || { fail "pacman -S $pkg_linux nie powiodło się."; return 1; }
    else
        fail "Nieznany package manager. Zainstaluj $label ręcznie."
        return 1
    fi
}

# ── Docker ────────────────────────────────────────────────────────────────────

step "Sprawdzam Docker..."

if ! command -v docker &>/dev/null; then
    fail "Docker nie jest zainstalowany."
    if [[ "$OS" == "macos" ]]; then
        info "Pobierz Docker Desktop: https://www.docker.com/products/docker-desktop"
    else
        info "Zainstaluj Docker: https://docs.docker.com/engine/install/"
        info "Lub użyj convenience script: curl -fsSL https://get.docker.com | sh"
    fi
    echo ""
    read -rp "  Naciśnij Enter po zainstalowaniu Dockera..."
    if ! command -v docker &>/dev/null; then
        fail "Docker nadal niedostępny. Przerywam."
        exit 1
    fi
fi

DOCKER_VER=$(docker --version 2>&1 | head -1)
ok "$DOCKER_VER"

# Sprawdź czy Docker daemon działa
if ! docker info &>/dev/null; then
    fail "Docker daemon nie działa."
    if [[ "$OS" == "macos" ]]; then
        info "Uruchom Docker Desktop z folderu Aplikacje."
    else
        info "Uruchom: sudo systemctl start docker"
        info "Autostart: sudo systemctl enable docker"
    fi
    echo ""
    read -rp "  Naciśnij Enter gdy Docker będzie uruchomiony..."
    if ! docker info &>/dev/null; then
        # Ostatnia szansa z sudo
        if sudo docker info &>/dev/null 2>&1; then
            warn "Docker działa tylko z sudo. Dodaj użytkownika do grupy docker:"
            info "  sudo usermod -aG docker \$USER  && newgrp docker"
        else
            fail "Docker daemon nadal niedostępny. Przerywam."
            exit 1
        fi
    fi
fi

ok "Docker daemon działa"

# Sprawdź Docker Compose (v2 — 'docker compose')
step "Sprawdzam Docker Compose..."

if docker compose version &>/dev/null 2>&1; then
    COMPOSE_VER=$(docker compose version 2>&1 | head -1)
    ok "$COMPOSE_VER"
else
    fail "Docker Compose v2 nie jest dostępny ('docker compose' zamiast 'docker-compose')."
    if [[ "$OS" == "macos" ]]; then
        info "Zaktualizuj Docker Desktop do najnowszej wersji."
    else
        info "Zainstaluj docker-compose-plugin:"
        info "  sudo apt-get install docker-compose-plugin   # Ubuntu/Debian"
        info "  sudo dnf install docker-compose-plugin       # Fedora"
    fi
    exit 1
fi

# ── Python ────────────────────────────────────────────────────────────────────

step "Sprawdzam Python 3.10+..."

PYTHON_CMD=""
for cmd in python3.12 python3.11 python3.10 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
        MAJOR=$(echo "$VER" | cut -d. -f1)
        MINOR=$(echo "$VER" | cut -d. -f2)
        if [[ "$MAJOR" -ge 3 && "$MINOR" -ge 10 ]]; then
            PYTHON_CMD="$cmd"
            ok "Python $VER ($cmd)"
            break
        fi
    fi
done

if [[ -z "$PYTHON_CMD" ]]; then
    warn "Python 3.10+ nie znaleziony."
    if [[ "$OS" == "macos" ]]; then
        if command -v brew &>/dev/null; then
            brew install python@3.12 && PYTHON_CMD="python3"
        else
            fail "Zainstaluj Python 3.10+ ze strony https://python.org"
            exit 1
        fi
    elif [[ "$PKG_MANAGER" == "apt" ]]; then
        sudo apt-get update -qq && sudo apt-get install -y python3 python3-pip && PYTHON_CMD="python3"
    elif [[ "$PKG_MANAGER" == "dnf" ]]; then
        sudo dnf install -y python3 python3-pip && PYTHON_CMD="python3"
    else
        fail "Zainstaluj Python 3.10+ ręcznie: https://python.org"
        exit 1
    fi
fi

# ── nmap ─────────────────────────────────────────────────────────────────────

step "Sprawdzam nmap (wymagany przez skaner discovery)..."

if command -v nmap &>/dev/null; then
    NMAP_VER=$(nmap --version 2>&1 | head -1)
    ok "$NMAP_VER"
else
    install_pkg "nmap" "nmap" "nmap" && ok "nmap zainstalowany" || {
        warn "nmap niedostępny — skaner discovery nie będzie działał."
        info "Zainstaluj ręcznie: https://nmap.org/download.html"
    }
fi

# ── git ───────────────────────────────────────────────────────────────────────

step "Sprawdzam git..."

if command -v git &>/dev/null; then
    ok "$(git --version)"
else
    install_pkg "git" "git" "git" && ok "git zainstalowany"
fi

# ── Plik .env ─────────────────────────────────────────────────────────────────

step "Konfiguruję plik .env..."

cd "$SCRIPT_DIR"

if [[ -f ".env" ]]; then
    ok ".env już istnieje — pomijam"
else
    if [[ -f ".env.example" ]]; then
        cp .env.example .env
        ok ".env skopiowany z .env.example"
        info "Edytuj .env aby ustawić NETWORK_RANGES, TELEGRAM_BOT_TOKEN itp."
        info "Domyślne ustawienia pozwolą uruchomić system bez zmian."
    else
        fail ".env.example nie znaleziony. Upewnij się że jesteś w katalogu projektu."
        exit 1
    fi
fi

# ── Zależności Pythona ────────────────────────────────────────────────────────

step "Instaluję zależności Pythona (requirements.txt)..."

if [[ -f "requirements.txt" ]]; then
    "$PYTHON_CMD" -m pip install -r requirements.txt -q --break-system-packages 2>/dev/null \
        || "$PYTHON_CMD" -m pip install -r requirements.txt -q \
        || warn "Część zależności mogła się nie zainstalować — sprawdź ręcznie."
    ok "Zależności Python zainstalowane"
else
    warn "requirements.txt nie znaleziony — pomijam"
fi

# ── Docker containers ─────────────────────────────────────────────────────────

step "Uruchamiam kontenery Docker (docker compose up -d)..."

# Port 514 (syslog) na Linux wymaga root lub CAP_NET_BIND_SERVICE
if [[ "$OS" == "linux" ]]; then
    if [[ $EUID -ne 0 ]]; then
        info "Uwaga: rsyslog nasłuchuje na porcie 514 (syslog)."
        info "Jeśli kontenery mają problem z portem 514, uruchom:"
        info "  sudo setcap cap_net_bind_service=+eip \$(which docker)  # zwykle niepotrzebne"
        info "  lub zmień port w docker-compose.yml na >1024"
    fi
fi

docker compose up -d
ok "Kontenery uruchomione"

# ── Czekaj na panel web ───────────────────────────────────────────────────────

step "Czekam aż panel Web będzie dostępny (http://localhost)..."

TIMEOUT=120
WAITED=0
until curl -sf "http://localhost/" -o /dev/null 2>/dev/null; do
    if [[ $WAITED -ge $TIMEOUT ]]; then
        warn "Panel nie odpowiedział po ${TIMEOUT}s — sprawdź: docker compose logs web"
        break
    fi
    printf "."
    sleep 3
    WAITED=$((WAITED + 3))
done
echo ""

if curl -sf "http://localhost/" -o /dev/null 2>/dev/null; then
    ok "Panel Web dostępny: http://localhost"
fi

# ── Pierwsze skanowanie sieci ─────────────────────────────────────────────────

step "Uruchamiam pierwsze skanowanie sieci..."

if [[ -f "run_scanner.py" ]]; then
    if command -v nmap &>/dev/null; then
        info "Skanowanie może potrwać 2–5 minut. Uruchamiam w tle..."
        nohup "$PYTHON_CMD" run_scanner.py --once > logs/scanner.log 2>&1 &
        SCANNER_PID=$!
        ok "Skaner uruchomiony (PID: $SCANNER_PID)"
        info "Wyniki w panelu: http://localhost/devices"
    else
        warn "nmap niedostępny — pomijam skanowanie."
        info "Uruchom ręcznie po zainstalowaniu nmap: python run_scanner.py --once"
    fi
else
    warn "run_scanner.py nie znaleziony — pomijam skanowanie."
fi

# ── Autostart skanera ─────────────────────────────────────────────────────────

step "Konfiguracja autostartu skanera..."

CRON_CMD="*/5 * * * * cd $SCRIPT_DIR && $PYTHON_CMD run_scanner.py --once >> $SCRIPT_DIR/logs/scanner.log 2>&1"

if command -v crontab &>/dev/null; then
    CURRENT_CRON=$(crontab -l 2>/dev/null || echo "")
    if echo "$CURRENT_CRON" | grep -q "run_scanner.py"; then
        ok "Cron job już skonfigurowany"
    else
        echo ""
        read -rp "  Dodać autostart skanera do crontab (co 5 minut)? [T/n]: " ADD_CRON
        if [[ "${ADD_CRON,,}" != "n" ]]; then
            (echo "$CURRENT_CRON"; echo "$CRON_CMD") | grep -v "^$" | crontab -
            ok "Cron job dodany (co 5 minut)"
        else
            info "Pomijam crontab. Możesz dodać ręcznie:"
            info "  crontab -e"
            info "  Dodaj: $CRON_CMD"
        fi
    fi
else
    warn "crontab niedostępny. Autostart skanera skonfiguruj ręcznie."
fi

# ── Otwórz przeglądarkę ────────────────────────────────────────────────────────

if curl -sf "http://localhost/" -o /dev/null 2>/dev/null; then
    if [[ "$OS" == "macos" ]]; then
        open "http://localhost/devices" 2>/dev/null || true
    elif command -v xdg-open &>/dev/null; then
        xdg-open "http://localhost/devices" 2>/dev/null || true
    fi
fi

# ── Podsumowanie ───────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}  ================================================${NC}"
echo -e "${CYAN}   NetDoc — instalacja zakończona!${NC}"
echo -e "${CYAN}  ================================================${NC}"
echo ""
echo -e "   Panel Admin   ${CYAN}http://localhost${NC}"
echo -e "   API / Swagger ${CYAN}http://localhost:8000/docs${NC}"
echo -e "   Grafana        ${CYAN}http://localhost/grafana${NC}   ${GRAY}(admin / netdoc)${NC}"
echo ""
echo -e "${GRAY}  Zarządzanie kontenerami:${NC}"
echo -e "${GRAY}    docker compose ps          # status${NC}"
echo -e "${GRAY}    docker compose logs -f web # logi panelu${NC}"
echo -e "${GRAY}    docker compose down        # zatrzymaj${NC}"
echo ""
echo -e "${GRAY}  Ręczne skanowanie:${NC}"
echo -e "${GRAY}    $PYTHON_CMD run_scanner.py --once${NC}"
echo ""
