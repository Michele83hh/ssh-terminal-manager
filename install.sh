#!/bin/bash
#
# SSH Terminal Manager - CLI Installation Script
# For Kali Linux and other Debian-based systems
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════╗"
echo "║   SSH Terminal Manager - CLI Installer    ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    SUDO=""
    echo -e "${YELLOW}[*] Running as root${NC}"
else
    SUDO="sudo"
    echo -e "${YELLOW}[*] Will use sudo for system-wide installation${NC}"
fi

# Detect installation directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/ssh-terminal-manager"
BIN_LINK="/usr/local/bin/sshm"

echo -e "${BLUE}[i] Source directory: ${SCRIPT_DIR}${NC}"
echo -e "${BLUE}[i] Install directory: ${INSTALL_DIR}${NC}"
echo ""

# Check Python
echo -e "${YELLOW}[1/5] Checking Python...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    echo -e "${GREEN}[+] Python ${PYTHON_VERSION} found${NC}"
else
    echo -e "${RED}[!] Python 3 not found. Installing...${NC}"
    $SUDO apt-get update
    $SUDO apt-get install -y python3 python3-pip python3-venv
fi

# Install system dependencies
echo -e "${YELLOW}[2/5] Installing system dependencies...${NC}"
$SUDO apt-get update
$SUDO apt-get install -y \
    python3-pip \
    python3-venv \
    libffi-dev \
    libssl-dev \
    2>/dev/null || true
echo -e "${GREEN}[+] System dependencies installed${NC}"

# Copy files to installation directory
echo -e "${YELLOW}[3/5] Installing application...${NC}"
$SUDO mkdir -p "$INSTALL_DIR"
$SUDO cp -r "$SCRIPT_DIR/src" "$INSTALL_DIR/"
$SUDO cp "$SCRIPT_DIR/ssh_manager_cli.py" "$INSTALL_DIR/"
$SUDO cp "$SCRIPT_DIR/requirements-cli.txt" "$INSTALL_DIR/"
$SUDO mkdir -p "$INSTALL_DIR/data"
$SUDO chmod 755 "$INSTALL_DIR"
echo -e "${GREEN}[+] Files copied to ${INSTALL_DIR}${NC}"

# Create virtual environment and install dependencies
echo -e "${YELLOW}[4/5] Setting up Python environment...${NC}"
$SUDO python3 -m venv "$INSTALL_DIR/venv"
$SUDO "$INSTALL_DIR/venv/bin/pip" install --upgrade pip
$SUDO "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements-cli.txt"
echo -e "${GREEN}[+] Python dependencies installed${NC}"

# Create launcher script
echo -e "${YELLOW}[5/5] Creating launcher command 'sshm'...${NC}"
$SUDO tee "$BIN_LINK" > /dev/null << 'LAUNCHER'
#!/bin/bash
#
# SSH Terminal Manager - CLI Launcher
#
INSTALL_DIR="/opt/ssh-terminal-manager"
exec "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/ssh_manager_cli.py" "$@"
LAUNCHER

$SUDO chmod +x "$BIN_LINK"
echo -e "${GREEN}[+] Command 'sshm' created${NC}"

# Set secure permissions for data directory
$SUDO chmod 700 "$INSTALL_DIR/data"
$SUDO chown "$USER:$USER" "$INSTALL_DIR/data"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Installation Complete!            ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo ""
echo -e "Usage:"
echo -e "  ${BLUE}sshm${NC}              - Interactive menu"
echo -e "  ${BLUE}sshm list${NC}         - List connections"
echo -e "  ${BLUE}sshm connect NAME${NC} - Connect to saved connection"
echo -e "  ${BLUE}sshm quick user@host${NC} - Quick connect"
echo ""
echo -e "${YELLOW}[*] First run will ask for a master password${NC}"
echo ""
