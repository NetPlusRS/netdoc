#!/usr/bin/env bash
# netdoc-setup.sh
# NetDoc installer for Linux and macOS.
# Checks requirements, configures the environment, and starts the system.
#
# Usage:
#   chmod +x netdoc-setup.sh
#   ./netdoc-setup.sh

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
GRAY='\033[0;90m'
NC='\033[0m'

step()  { echo -e "\n${CYAN}  >> $*${NC}"; }
ok()    { echo -e "${GREEN}     [OK] $*${NC}"; }
warn()  { echo -e "${YELLOW}     [!!] $*${NC}"; }
fail()  { echo -e "${RED}     [FAIL] $*${NC}"; }
info()  { echo -e "${GRAY}           $*${NC}"; }

# ── OS and package manager detection ──────────────────────────────────────────

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

# ── Header ────────────────────────────────────────────────────────────────────

clear
echo -e "${CYAN}"
echo "  ================================================"
echo "   NetDoc  —  Installer for Linux / macOS"
echo "  ================================================"
echo -e "${NC}"
echo -e "${GRAY}  Project directory: $SCRIPT_DIR${NC}"

detect_os

echo -e "${GRAY}  OS:              $OS${NC}"
[[ "$OS" == "linux" ]] && echo -e "${GRAY}  Package manager: $PKG_MANAGER${NC}"
echo ""

# ── Package installation function ────────────────────────────────────────────

install_pkg() {
    local pkg_linux="$1"
    local pkg_brew="$2"
    local label="$3"

    warn "$label not found — attempting to install..."

    if [[ "$OS" == "macos" ]]; then
        if command -v brew &>/dev/null; then
            brew install "$pkg_brew" || { fail "Failed to install $label via Homebrew."; return 1; }
        else
            fail "Homebrew is not installed. Install it from https://brew.sh"
            info "Then run: brew install $pkg_brew"
            return 1
        fi
    elif [[ "$PKG_MANAGER" == "apt" ]]; then
        sudo apt-get update -qq && sudo apt-get install -y "$pkg_linux" || { fail "apt install $pkg_linux failed."; return 1; }
    elif [[ "$PKG_MANAGER" == "dnf" ]]; then
        sudo dnf install -y "$pkg_linux" || { fail "dnf install $pkg_linux failed."; return 1; }
    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        sudo yum install -y "$pkg_linux" || { fail "yum install $pkg_linux failed."; return 1; }
    elif [[ "$PKG_MANAGER" == "pacman" ]]; then
        sudo pacman -S --noconfirm "$pkg_linux" || { fail "pacman -S $pkg_linux failed."; return 1; }
    else
        fail "Unknown package manager. Please install $label manually."
        return 1
    fi
}

# ── Docker ────────────────────────────────────────────────────────────────────

step "Checking Docker..."

if ! command -v docker &>/dev/null; then
    fail "Docker is not installed."
    if [[ "$OS" == "macos" ]]; then
        info "Download Docker Desktop: https://www.docker.com/products/docker-desktop"
    else
        info "Install Docker: https://docs.docker.com/engine/install/"
        info "Or use the convenience script: curl -fsSL https://get.docker.com | sh"
    fi
    echo ""
    read -rp "  Press Enter after installing Docker..."
    if ! command -v docker &>/dev/null; then
        fail "Docker is still unavailable. Aborting."
        exit 1
    fi
fi

DOCKER_VER=$(docker --version 2>&1 | head -1)
ok "$DOCKER_VER"

# Check whether the Docker daemon is running
if ! docker info &>/dev/null; then
    fail "Docker daemon is not running or not accessible without sudo."
    if [[ "$OS" == "macos" ]]; then
        info "Launch Docker Desktop from the Applications folder."
        echo ""
        read -rp "  Press Enter once Docker is running..."
    else
        # Linux: sprawdz czy to kwestia grupy docker czy daemon nie dziala
        if sudo docker info &>/dev/null 2>&1; then
            warn "Docker requires sudo — your user is not in the 'docker' group."
            echo ""
            read -rp "  Add user '$USER' to the docker group? [Y/n]: " FIX_DOCKER_GROUP
            if [[ "${FIX_DOCKER_GROUP,,}" != "n" ]]; then
                sudo usermod -aG docker "$USER"
                ok "User '$USER' added to 'docker' group."
                warn "Group change takes effect in a new shell session."
                info "Continuing with 'newgrp docker' for this session..."
                # Uruchom resztę skryptu w nowej sesji grupy docker
                exec sg docker -c "bash '$0' --skip-group-fix"
                # exec nie wraca — jesli sg zawiedzie, kontynuuj z sudo
            fi
            # Fallback: uzyj sudo dla pozostalych komend docker
            export DOCKER_CMD="sudo docker"
        else
            info "Run: sudo systemctl start docker"
            info "Enable on boot: sudo systemctl enable docker"
            echo ""
            read -rp "  Press Enter once Docker is running..."
            if ! docker info &>/dev/null 2>&1 && ! sudo docker info &>/dev/null 2>&1; then
                fail "Docker daemon is still unavailable. Aborting."
                exit 1
            fi
            export DOCKER_CMD="sudo docker"
        fi
    fi
fi
DOCKER_CMD="${DOCKER_CMD:-docker}"

ok "Docker daemon is running"

# Check Docker Compose (v2 — 'docker compose')
step "Checking Docker Compose..."

if $DOCKER_CMD compose version &>/dev/null 2>&1; then
    COMPOSE_VER=$($DOCKER_CMD compose version 2>&1 | head -1)
    ok "$COMPOSE_VER"
else
    fail "Docker Compose v2 is not available ('docker compose' plugin missing)."
    if [[ "$OS" == "macos" ]]; then
        info "Update Docker Desktop to the latest version."
    elif [[ "$PKG_MANAGER" == "apt" ]]; then
        # docker-compose-plugin jest w oficjalnym repo Docker (nie Ubuntu default).
        # Jesli Docker byl instalowany przez get.docker.com — plugin juz powinien byc.
        # Jesli przez apt install docker.io — potrzeba repo Docker.
        info "Attempting to install docker-compose-plugin..."
        if sudo apt-get install -y docker-compose-plugin 2>/dev/null; then
            ok "docker-compose-plugin installed"
        else
            info "If the above failed, add the Docker official apt repository first:"
            info "  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg"
            info "  echo \"deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \$(lsb_release -cs) stable\" | sudo tee /etc/apt/sources.list.d/docker.list"
            info "  sudo apt-get update && sudo apt-get install -y docker-compose-plugin"
            exit 1
        fi
    elif [[ "$PKG_MANAGER" == "dnf" ]]; then
        sudo dnf install -y docker-compose-plugin || exit 1
    else
        exit 1
    fi
    # Weryfikacja po instalacji
    $DOCKER_CMD compose version &>/dev/null 2>&1 || { fail "docker compose still not available"; exit 1; }
    ok "$($DOCKER_CMD compose version 2>&1 | head -1)"
fi

# ── Python ────────────────────────────────────────────────────────────────────

step "Checking Python 3.10+..."

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
    warn "Python 3.10+ not found — attempting to install..."
    if [[ "$OS" == "macos" ]]; then
        if command -v brew &>/dev/null; then
            brew install python@3.12 && PYTHON_CMD="python3.12"
        else
            fail "Install Python 3.10+ from https://python.org"
            exit 1
        fi
    elif [[ "$PKG_MANAGER" == "apt" ]]; then
        # Ubuntu 20.04: domyslny python3 = 3.8 (za stary). Proba python3.12 z deadsnakes PPA.
        sudo apt-get update -qq
        if sudo apt-get install -y python3.12 python3.12-venv 2>/dev/null; then
            PYTHON_CMD="python3.12"
            ok "Python 3.12 installed from system packages"
        else
            # Fallback: deadsnakes PPA (Ubuntu 20.04)
            info "Trying deadsnakes PPA for Python 3.12..."
            sudo apt-get install -y software-properties-common -qq
            sudo add-apt-repository ppa:deadsnakes/ppa -y
            sudo apt-get update -qq
            sudo apt-get install -y python3.12 python3.12-venv && PYTHON_CMD="python3.12"
        fi
    elif [[ "$PKG_MANAGER" == "dnf" ]]; then
        sudo dnf install -y python3.12 python3.12-venv && PYTHON_CMD="python3.12"
    else
        fail "Install Python 3.10+ manually: https://python.org"
        exit 1
    fi
fi

# ── nmap ─────────────────────────────────────────────────────────────────────

step "Checking nmap (required by the discovery scanner)..."

if command -v nmap &>/dev/null; then
    NMAP_VER=$(nmap --version 2>&1 | head -1)
    ok "$NMAP_VER"
else
    install_pkg "nmap" "nmap" "nmap" && ok "nmap installed" || {
        warn "nmap unavailable — discovery scanner will not work."
        info "Install manually: https://nmap.org/download.html"
    }
fi

# ── curl (wymagany do sprawdzania panelu webowego) ────────────────────────────

step "Checking curl..."

if command -v curl &>/dev/null; then
    ok "$(curl --version 2>&1 | head -1)"
else
    install_pkg "curl" "curl" "curl" && ok "curl installed"
fi

# ── git ───────────────────────────────────────────────────────────────────────

step "Checking git..."

if command -v git &>/dev/null; then
    ok "$(git --version)"
else
    install_pkg "git" "git" "git" && ok "git installed"
fi

# ── .env file ─────────────────────────────────────────────────────────────────

step "Configuring .env file..."

cd "$SCRIPT_DIR"

if [[ -f ".env" ]]; then
    ok ".env already exists — skipping"
else
    if [[ -f ".env.example" ]]; then
        cp .env.example .env
        ok ".env copied from .env.example"
        info "Edit .env to set NETWORK_RANGES, TELEGRAM_BOT_TOKEN, etc."
        info "Default settings allow the system to start without any changes."
    else
        fail ".env.example not found. Make sure you are in the project directory."
        exit 1
    fi
fi

# ── Python dependencies (virtualenv) ──────────────────────────────────────────
# Uzywamy virtualenv zamiast bezposredniego pip install, bo:
# - Ubuntu 22.04+: PEP 668 "externally managed environment" blokuje pip install
# - --break-system-packages nie istnieje w pip < 23.1 (Ubuntu 22.04 ma pip 22.x)
# - venv izoluje zaleznosci i dziala wszedie bez sudo

step "Setting up Python virtual environment (.venv)..."

# Upewnij sie ze python3-venv/python3.X-venv jest zainstalowany
if ! "$PYTHON_CMD" -m venv --help &>/dev/null 2>&1; then
    warn "venv module not available — installing..."
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        PY_MINOR=$("$PYTHON_CMD" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo "")
        PY_MAJOR=$("$PYTHON_CMD" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo "3")
        if [[ -n "$PY_MINOR" ]]; then
            sudo apt-get install -y "python${PY_MAJOR}.${PY_MINOR}-venv" 2>/dev/null \
                || sudo apt-get install -y python3-venv
        else
            sudo apt-get install -y python3-venv
        fi
    elif [[ "$PKG_MANAGER" == "dnf" ]]; then
        sudo dnf install -y python3-venv
    fi
fi

VENV_DIR="$SCRIPT_DIR/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
    "$PYTHON_CMD" -m venv "$VENV_DIR" || { fail "Failed to create virtualenv at $VENV_DIR"; exit 1; }
    ok "Virtualenv created: $VENV_DIR"
else
    ok "Virtualenv already exists: $VENV_DIR"
fi

# Uzyj Pythona z venv do instalacji zaleznosci
VENV_PYTHON="$VENV_DIR/bin/python"
[[ "$OS" == "macos" ]] && VENV_PYTHON="$VENV_DIR/bin/python3"

step "Installing Python dependencies (requirements.txt)..."

if [[ -f "requirements.txt" ]]; then
    "$VENV_PYTHON" -m pip install --upgrade pip -q
    "$VENV_PYTHON" -m pip install -r requirements.txt -q \
        || { fail "pip install failed — check requirements.txt and network access."; exit 1; }
    ok "Python dependencies installed"
else
    warn "requirements.txt not found — skipping"
fi

# Playwright — wymaga oddzielnej instalacji przegladarki i bibliotek systemowych
# Bez tego screenshots (hover preview) nie beda dzialac (brak chromium / brakujace .so)
step "Installing Playwright browser (chromium) + system deps..."
if "$VENV_PYTHON" -c "import playwright" 2>/dev/null; then
    "$VENV_PYTHON" -m playwright install chromium --with-deps 2>/dev/null \
        && ok "Playwright chromium installed" \
        || warn "Playwright install failed — screenshot preview will be unavailable."
else
    warn "Playwright not in requirements — skipping browser install."
fi

# Od teraz uzywamy VENV_PYTHON zamiast PYTHON_CMD
PYTHON_CMD="$VENV_PYTHON"

# ── Detect previous installation ─────────────────────────────────────────────

step "Checking for a previous NetDoc installation..."

OLD_CONTAINERS=$($DOCKER_CMD ps -a --filter "name=netdoc" --format "{{.Names}}" 2>/dev/null | grep -v "^$" || true)
OLD_VOLUMES=$($DOCKER_CMD volume ls --filter "name=netdoc" --format "{{.Name}}" 2>/dev/null | grep -v "^$" || true)

if [[ -n "$OLD_CONTAINERS" || -n "$OLD_VOLUMES" ]]; then
    warn "A previous NetDoc installation was found:"
    if [[ -n "$OLD_CONTAINERS" ]]; then
        info "  Containers:"
        echo "$OLD_CONTAINERS" | while read -r c; do info "    - $c"; done
    fi
    if [[ -n "$OLD_VOLUMES" ]]; then
        info "  Volumes:"
        echo "$OLD_VOLUMES" | while read -r v; do info "    - $v"; done
    fi

    echo ""
    echo "  You have two options:"
    echo -e "   ${YELLOW}[Y]${NC}  Remove old containers and data (clean install)"
    echo -e "       ${GRAY}WARNING: this will delete the database, metrics, and configuration!${NC}"
    echo -e "   ${CYAN}[N]${NC}  Keep existing data (upgrade / restart)"
    echo -e "       ${GRAY}Old containers will be stopped; data will be preserved.${NC}"
    echo ""

    read -rp "  Remove old data and perform a clean install? [Y/n]: " CLEAN_UP
    CLEAN_UP="${CLEAN_UP,,}"

    if [[ "$CLEAN_UP" == "y" ]]; then
        info "Removing old containers and volumes..."
        $DOCKER_CMD compose down --volumes --remove-orphans || true
        ok "Old containers and data removed — clean install."
    else
        info "Stopping old containers (data preserved)..."
        $DOCKER_CMD compose down --remove-orphans || true
        ok "Old containers stopped — volume data preserved."
    fi
else
    ok "No previous installation found — clean install."
fi

# ── Docker containers ─────────────────────────────────────────────────────────

step "Starting Docker containers (docker compose up -d)..."

# Port 514 (syslog) on Linux requires root or CAP_NET_BIND_SERVICE
if [[ "$OS" == "linux" ]]; then
    if [[ $EUID -ne 0 ]]; then
        info "Note: rsyslog listens on port 514 (syslog)."
        info "If containers have trouble binding port 514, run:"
        info "  sudo setcap cap_net_bind_service=+eip \$(which docker)  # usually not needed"
        info "  or change the port in docker-compose.yml to >1024"
    fi
fi

$DOCKER_CMD compose up -d
ok "Containers started"

# ── Wait for the web panel ───────────────────────────────────────────────────

step "Waiting for the Web panel to become available (http://localhost)..."

TIMEOUT=120
WAITED=0
until curl -sf "http://localhost/" -o /dev/null 2>/dev/null; do
    if [[ $WAITED -ge $TIMEOUT ]]; then
        warn "Panel did not respond after ${TIMEOUT}s — check: docker compose logs web"
        break
    fi
    printf "."
    sleep 3
    WAITED=$((WAITED + 3))
done
echo ""

if curl -sf "http://localhost/" -o /dev/null 2>/dev/null; then
    ok "Web panel available: http://localhost"
fi

# ── Initial network scan ─────────────────────────────────────────────────────

step "Running initial network scan..."

mkdir -p logs  # upewnij sie ze katalog logów istnieje

if [[ -f "run_scanner.py" ]]; then
    if command -v nmap &>/dev/null; then
        info "Scan may take 2–5 minutes. Starting in the background..."
        nohup "$PYTHON_CMD" run_scanner.py --once > logs/scanner.log 2>&1 &
        SCANNER_PID=$!
        ok "Scanner started (PID: $SCANNER_PID)"
        info "Results in the panel: http://localhost/devices"
    else
        warn "nmap unavailable — skipping scan."
        info "Run manually after installing nmap: python run_scanner.py --once"
    fi
else
    warn "run_scanner.py not found — skipping scan."
fi

# ── Scanner autostart ─────────────────────────────────────────────────────────

step "Configuring scanner autostart..."

# Cron musi uzywac absolutnej sciezki do python z venv (nie 'python3' z PATH)
CRON_CMD="*/5 * * * * cd $SCRIPT_DIR && $SCRIPT_DIR/.venv/bin/python run_scanner.py --once >> $SCRIPT_DIR/logs/scanner.log 2>&1"

if command -v crontab &>/dev/null; then
    CURRENT_CRON=$(crontab -l 2>/dev/null || echo "")
    if echo "$CURRENT_CRON" | grep -q "run_scanner.py"; then
        ok "Cron job already configured"
    else
        echo ""
        read -rp "  Add scanner autostart to crontab (every 5 minutes)? [Y/n]: " ADD_CRON
        if [[ "${ADD_CRON,,}" != "n" ]]; then
            (echo "$CURRENT_CRON"; echo "$CRON_CMD") | grep -v "^$" | crontab -
            ok "Cron job added (every 5 minutes)"
        else
            info "Skipping crontab. You can add it manually:"
            info "  crontab -e"
            info "  Add: $CRON_CMD"
        fi
    fi
else
    warn "crontab is unavailable. Configure scanner autostart manually."
fi

# ── Open browser ──────────────────────────────────────────────────────────────

if curl -sf "http://localhost/" -o /dev/null 2>/dev/null; then
    if [[ "$OS" == "macos" ]]; then
        open "http://localhost/devices" 2>/dev/null || true
    elif command -v xdg-open &>/dev/null; then
        xdg-open "http://localhost/devices" 2>/dev/null || true
    fi
fi

# ── Summary ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}  ================================================${NC}"
echo -e "${CYAN}   NetDoc — installation complete!${NC}"
echo -e "${CYAN}  ================================================${NC}"
echo ""
echo -e "   Admin Panel   ${CYAN}http://localhost${NC}"
echo -e "   API / Swagger ${CYAN}http://localhost:8000/docs${NC}"
echo -e "   Grafana        ${CYAN}http://localhost/grafana${NC}   ${GRAY}(admin / netdoc)${NC}"
echo ""
echo -e "${GRAY}  Container management:${NC}"
echo -e "${GRAY}    docker compose ps          # status${NC}"
echo -e "${GRAY}    docker compose logs -f web # panel logs${NC}"
echo -e "${GRAY}    docker compose down        # stop${NC}"
echo ""
echo -e "${GRAY}  Manual scan:${NC}"
echo -e "${GRAY}    $PYTHON_CMD run_scanner.py --once${NC}"
echo ""
