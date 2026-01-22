#!/bin/bash
#
# SSH Terminal Manager - Uninstall Script
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}SSH Terminal Manager - Uninstaller${NC}"
echo ""

if [ "$EUID" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

INSTALL_DIR="/opt/ssh-terminal-manager"
BIN_LINK="/usr/local/bin/sshm"

# Ask for confirmation
read -p "Remove SSH Terminal Manager? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Remove launcher
if [ -f "$BIN_LINK" ]; then
    $SUDO rm "$BIN_LINK"
    echo -e "${GREEN}[+] Removed ${BIN_LINK}${NC}"
fi

# Ask about data
if [ -d "$INSTALL_DIR/data" ]; then
    read -p "Also delete saved connections and credentials? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        $SUDO rm -rf "$INSTALL_DIR"
        echo -e "${GREEN}[+] Removed ${INSTALL_DIR} (including data)${NC}"
    else
        # Keep data, remove everything else
        $SUDO rm -rf "$INSTALL_DIR/venv"
        $SUDO rm -rf "$INSTALL_DIR/src"
        $SUDO rm -f "$INSTALL_DIR/ssh_manager_cli.py"
        $SUDO rm -f "$INSTALL_DIR/requirements-cli.txt"
        echo -e "${GREEN}[+] Removed application files${NC}"
        echo -e "${YELLOW}[*] Data preserved in ${INSTALL_DIR}/data${NC}"
    fi
else
    $SUDO rm -rf "$INSTALL_DIR"
    echo -e "${GREEN}[+] Removed ${INSTALL_DIR}${NC}"
fi

echo ""
echo -e "${GREEN}Uninstallation complete.${NC}"
