#!/usr/bin/env bash
# ============================================================================
# HostVigil - Host-Based Installation Script (Linux / macOS)
# ============================================================================
#
# Installs all dependencies and configures the environment for HostVigil.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# What it does:
#   1. Checks Python 3.11+ is available
#   2. Installs system dependencies (nmap, libpcap)
#   3. Optionally installs Nuclei vulnerability scanner
#   4. Optionally installs naabu port scanner (fast two-phase scanning)
#   5. Creates a Python virtual environment
#   6. Installs Python dependencies
#   7. Creates data directories
#   8. Initializes the database
#   8. Validates the installation
#
# ============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

BANNER='
  _   _           _  __     ___       _ _
 | | | | ___  ___| |_\ \   / (_) __ _(_) |
 | |_| |/ _ \/ __| __|\ \ / /| |/ _` | | |
 |  _  | (_) \__ \ |_  \ V / | | (_| | | |
 |_| |_|\___/|___/\__|  \_/  |_|\__, |_|_|
                                 |___/
        Stealth Internal Recon Platform
'

echo -e "${BLUE}${BANNER}${NC}"
echo -e "${BLUE}[*] HostVigil Installation Script${NC}"
echo "============================================"
echo ""

# Helpers
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
    else
        echo -e "${RED}[!] This script needs root privileges for package/tool installation.${NC}"
        echo "    Re-run as root or install sudo."
        exit 1
    fi
fi

run_privileged() {
    if [ -n "$SUDO" ]; then
        "$SUDO" "$@"
    else
        "$@"
    fi
}

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t hostvigil-install)"
cleanup_tmp() {
    rm -rf "$TMP_DIR"
}
trap cleanup_tmp EXIT

download_file() {
    local url="$1"
    local output="$2"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget &>/dev/null; then
        wget -q "$url" -O "$output"
    else
        echo -e "${RED}[!] Neither curl nor wget is available for downloads.${NC}"
        exit 1
    fi
}

fetch_latest_github_tag() {
    local repo="$1"
    local api_url="https://api.github.com/repos/${repo}/releases/latest"
    local response=""
    if command -v curl &>/dev/null; then
        response="$(curl -fsSL "$api_url")"
    elif command -v wget &>/dev/null; then
        response="$(wget -qO- "$api_url")"
    else
        echo -e "${RED}[!] Neither curl nor wget is available to query GitHub releases.${NC}"
        exit 1
    fi
    echo "$response" | awk -F'"' '/"tag_name":/ {print $4; exit}'
}

# ---------------------------------------------------------------------------
# 1. Check Python version
# ---------------------------------------------------------------------------
echo -e "${BLUE}[1/8] Checking Python version...${NC}"

PYTHON_CMD=""
for cmd in python3.13 python3.12 python3.11 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || true)
        [ -z "$ver" ] && continue
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 11 ]; }; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}[!] Python 3.11+ is required but not found.${NC}"
    echo "    Install it with:"
    echo "      Ubuntu/Debian: sudo apt install python3.11 python3.11-venv"
    echo "      Fedora:        sudo dnf install python3.11"
    echo "      macOS:         brew install python@3.11"
    exit 1
fi

echo -e "${GREEN}    Found: $($PYTHON_CMD --version)${NC}"

# ---------------------------------------------------------------------------
# 2. Install system dependencies
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[2/8] Installing system dependencies...${NC}"

install_linux_deps() {
    if command -v apt-get &>/dev/null; then
        # Debian/Ubuntu
        echo "    Detected: Debian/Ubuntu"
        run_privileged apt-get update -qq
        run_privileged apt-get install -y -qq nmap libpcap-dev tcpdump wget unzip curl
    elif command -v dnf &>/dev/null; then
        # Fedora/RHEL
        echo "    Detected: Fedora/RHEL"
        run_privileged dnf install -y nmap libpcap-devel tcpdump wget unzip curl
    elif command -v yum &>/dev/null; then
        # CentOS/older RHEL
        echo "    Detected: CentOS/RHEL"
        run_privileged yum install -y nmap libpcap-devel tcpdump wget unzip curl
    elif command -v pacman &>/dev/null; then
        # Arch Linux
        echo "    Detected: Arch Linux"
        run_privileged pacman -S --noconfirm nmap libpcap tcpdump wget unzip curl
    elif command -v apk &>/dev/null; then
        # Alpine
        echo "    Detected: Alpine"
        run_privileged apk add nmap libpcap-dev tcpdump wget unzip curl
    else
        echo -e "${YELLOW}    [!] Unknown package manager. Please install manually:${NC}"
        echo "        - nmap"
        echo "        - libpcap-dev (or libpcap-devel)"
        echo "        - tcpdump"
    fi
}

install_macos_deps() {
    if command -v brew &>/dev/null; then
        echo "    Detected: macOS (Homebrew)"
        brew install nmap libpcap wget unzip curl
    else
        echo -e "${YELLOW}    [!] Homebrew not found. Please install:${NC}"
        echo "        /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        echo "        Then: brew install nmap libpcap wget unzip curl"
    fi
}

OS="$(uname -s)"
case "$OS" in
    Linux*)  install_linux_deps ;;
    Darwin*) install_macos_deps ;;
    *)       echo -e "${YELLOW}    [!] Unsupported OS: $OS. Install nmap manually.${NC}" ;;
esac

# Verify nmap
if command -v nmap &>/dev/null; then
    echo -e "${GREEN}    nmap: $(nmap --version 2>&1 | head -1)${NC}"
else
    echo -e "${YELLOW}    [!] nmap not found in PATH. Install it before running HostVigil.${NC}"
fi

# ---------------------------------------------------------------------------
# 3. Install Nuclei (optional)
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[3/8] Installing Nuclei vulnerability scanner (optional)...${NC}"

if command -v nuclei &>/dev/null; then
    echo -e "${GREEN}    Nuclei already installed: $(nuclei -version 2>&1 | head -1)${NC}"
else
    echo -n "    Install Nuclei? (recommended for vuln scanning) [Y/n]: "
    read -r INSTALL_NUCLEI
    INSTALL_NUCLEI=${INSTALL_NUCLEI:-Y}

    if [[ "$INSTALL_NUCLEI" =~ ^[Yy] ]]; then
        echo "    Downloading latest Nuclei release..."
        ARCH="$(uname -m)"
        case "$ARCH" in
            x86_64|amd64) NUCLEI_ARCH="amd64" ;;
            aarch64|arm64) NUCLEI_ARCH="arm64" ;;
            *) echo -e "${YELLOW}    [!] Unsupported arch: $ARCH. Download manually from:${NC}"
               echo "        https://github.com/projectdiscovery/nuclei/releases"
               NUCLEI_ARCH="" ;;
        esac

        if [ -n "$NUCLEI_ARCH" ]; then
            NUCLEI_OS="linux"
            [ "$OS" = "Darwin" ] && NUCLEI_OS="darwin"

            NUCLEI_TAG="$(fetch_latest_github_tag 'projectdiscovery/nuclei')"
            if [ -z "$NUCLEI_TAG" ]; then
                echo -e "${RED}    [!] Failed to determine latest Nuclei version.${NC}"
                exit 1
            fi
            NUCLEI_VERSION="${NUCLEI_TAG#v}"
            NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_TAG}/nuclei_${NUCLEI_VERSION}_${NUCLEI_OS}_${NUCLEI_ARCH}.zip"

            NUCLEI_ZIP="$TMP_DIR/nuclei.zip"
            NUCLEI_EXTRACT="$TMP_DIR/nuclei_extract"
            mkdir -p "$NUCLEI_EXTRACT"

            download_file "$NUCLEI_URL" "$NUCLEI_ZIP"
            unzip -oq "$NUCLEI_ZIP" -d "$NUCLEI_EXTRACT"
            if [ ! -f "$NUCLEI_EXTRACT/nuclei" ]; then
                echo -e "${RED}    [!] Downloaded Nuclei archive did not contain nuclei binary.${NC}"
                exit 1
            fi
            run_privileged install -m 0755 "$NUCLEI_EXTRACT/nuclei" /usr/local/bin/nuclei

            # Update templates
            echo "    Updating Nuclei templates..."
            if ! nuclei -update-templates >/dev/null 2>&1; then
                echo -e "${YELLOW}    [!] Nuclei installed, but template update failed. Run 'nuclei -update-templates' later.${NC}"
            fi
            echo -e "${GREEN}    Nuclei installed: $(nuclei -version 2>&1 | head -1)${NC}"
        fi
    else
        echo "    Skipped. You can install later from: https://github.com/projectdiscovery/nuclei/releases"
    fi
fi

# ---------------------------------------------------------------------------
# 4. Install naabu (optional - for fast two-phase port scanning)
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[4/8] Installing naabu port scanner (optional)...${NC}"

if command -v naabu &>/dev/null; then
    echo -e "${GREEN}    naabu already installed: $(naabu -version 2>&1 | head -1)${NC}"
else
    echo -e "${YELLOW}    Installing naabu...${NC}"
    # Method 1: Go install (if Go is available)
    if command -v go &>/dev/null; then
        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
        # Symlink to /usr/local/bin if installed to ~/go/bin
        if [ -f "$HOME/go/bin/naabu" ] && [ ! -f "/usr/local/bin/naabu" ]; then
            sudo ln -sf "$HOME/go/bin/naabu" /usr/local/bin/naabu
        fi
    # Method 2: Download binary
    elif [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
        NAABU_TAG="$(fetch_latest_github_tag 'projectdiscovery/naabu')"
        if [ -z "$NAABU_TAG" ]; then
            echo -e "${RED}    [!] Failed to determine latest naabu version.${NC}"
            exit 1
        fi
        NAABU_VERSION="${NAABU_TAG#v}"

        ARCH="$(uname -m)"
        case "$ARCH" in
            x86_64|amd64) NAABU_ARCH="amd64" ;;
            aarch64|arm64) NAABU_ARCH="arm64" ;;
            *) echo -e "${YELLOW}    [!] Unsupported arch for binary download: $ARCH${NC}"
               NAABU_ARCH="" ;;
        esac

        if [ -n "$NAABU_ARCH" ]; then
            NAABU_OS="linux"
            [ "$OS" = "Darwin" ] && NAABU_OS="darwin"
            NAABU_URL="https://github.com/projectdiscovery/naabu/releases/download/${NAABU_TAG}/naabu_${NAABU_VERSION}_${NAABU_OS}_${NAABU_ARCH}.zip"
            NAABU_ZIP="$TMP_DIR/naabu.zip"
            NAABU_EXTRACT="$TMP_DIR/naabu_extract"
            mkdir -p "$NAABU_EXTRACT"
            download_file "$NAABU_URL" "$NAABU_ZIP"
            unzip -oq "$NAABU_ZIP" -d "$NAABU_EXTRACT"
            if [ -f "$NAABU_EXTRACT/naabu" ]; then
                run_privileged install -m 0755 "$NAABU_EXTRACT/naabu" /usr/local/bin/naabu
            else
                echo -e "${YELLOW}    [!] naabu binary missing from downloaded archive.${NC}"
            fi
        elif [[ "$OSTYPE" == "darwin"* ]] && command -v brew &>/dev/null; then
            echo "    Falling back to Homebrew install for naabu..."
            brew install naabu
        fi
    fi
    
    if command -v naabu &>/dev/null; then
        echo -e "${GREEN}    ✓ naabu installed successfully${NC}"
    else
        echo -e "${YELLOW}    ⚠ naabu installation failed (optional - two_phase mode won't work)${NC}"
    fi
fi

# ---------------------------------------------------------------------------
# 5. Create Python virtual environment
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[5/8] Setting up Python virtual environment...${NC}"

if [ -d "venv" ]; then
    echo "    Virtual environment already exists at ./venv"
    echo -n "    Recreate? [y/N]: "
    read -r RECREATE_VENV
    if [[ "$RECREATE_VENV" =~ ^[Yy] ]]; then
        rm -rf venv
        $PYTHON_CMD -m venv venv
        echo -e "${GREEN}    Virtual environment recreated.${NC}"
    fi
else
    $PYTHON_CMD -m venv venv
    echo -e "${GREEN}    Virtual environment created at ./venv${NC}"
fi

# Activate
source venv/bin/activate
echo "    Activated: $(python --version) @ $(which python)"

# ---------------------------------------------------------------------------
# 5. Install Python dependencies
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[6/8] Installing Python dependencies...${NC}"

python -m pip install --upgrade pip setuptools wheel -q
python -m pip install -r requirements.txt -q

echo -e "${GREEN}    All Python packages installed.${NC}"

# ---------------------------------------------------------------------------
# 6. Create data directories
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[7/8] Creating data directories...${NC}"

mkdir -p data/logs data/models data/scans data/reports plugins
echo -e "${GREEN}    Created: data/{logs,models,scans,reports}, plugins/${NC}"

# ---------------------------------------------------------------------------
# 7. Initialize database and validate
# ---------------------------------------------------------------------------
echo ""
echo -e "${BLUE}[8/8] Initializing database and validating...${NC}"

python -c "from hostvigil.utils import init_database; init_database(); print('    Database initialized: data/hostvigil.db')"

# Quick validation
echo ""
echo "    Running validation checks..."
python -c "
from hostvigil.config import Config
from hostvigil.orchestrator import HostVigilOrchestrator
import shutil

checks_ok = 0
checks_total = 0

# Check nmap
checks_total += 1
nmap = shutil.which('nmap')
if nmap:
    print(f'      [OK] nmap: {nmap}')
    checks_ok += 1
else:
    print('      [!!] nmap: NOT FOUND')

# Check nuclei
checks_total += 1
nuclei = shutil.which('nuclei')
if nuclei:
    print(f'      [OK] nuclei: {nuclei}')
    checks_ok += 1
else:
    print('      [--] nuclei: not installed (optional)')
    checks_ok += 1  # optional

# Check naabu
checks_total += 1
naabu = shutil.which('naabu')
if naabu:
    print(f'      [OK] naabu: {naabu}')
    checks_ok += 1
else:
    print('      [--] naabu: not installed (optional, for two-phase mode)')
    checks_ok += 1  # optional

# Check config
checks_total += 1
try:
    Config('config.yaml')
    print('      [OK] config.yaml: valid')
    checks_ok += 1
except Exception as e:
    print(f'      [!!] config.yaml: {e}')

# Check modules
checks_total += 1
try:
    from hostvigil.discovery import StealthDiscovery
    from hostvigil.scanner import StealthScanner
    from hostvigil.ml_engine import AnomalyDetector
    from hostvigil.nuclei import NucleiRunner
    from hostvigil.dashboard import create_app
    print('      [OK] All modules import successfully')
    checks_ok += 1
except Exception as e:
    print(f'      [!!] Module import failed: {e}')

print(f'\n    Checks passed: {checks_ok}/{checks_total}')
"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo -e "${GREEN}[+] Installation complete!${NC}"
echo ""
echo "  To start HostVigil:"
echo "    source venv/bin/activate"
echo "    python run.py daemon"
echo ""
echo "  Dashboard will be available at:"
echo "    http://127.0.0.1:5000"
echo "    Login: admin / hostvigil"
echo ""
echo "  For 200k+ host networks:"
echo "    python run.py -c entp_config.yaml daemon"
echo ""
echo "  Other commands:"
echo "    python run.py --help"
echo "    python run.py status"
echo "    python run.py doctor"
echo ""
echo -e "${YELLOW}  ⚠️  For ARP/SYN scans, run with sudo or as root.${NC}"
echo "============================================"
