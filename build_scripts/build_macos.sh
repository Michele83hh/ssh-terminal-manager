#!/bin/bash
# macOS Build Script for SSH Terminal Manager
# Creates a .app bundle and optionally a .dmg installer

set -e

echo "========================================"
echo "SSH Terminal Manager - macOS Build"
echo "========================================"

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "ERROR: This script must be run on macOS"
    exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found"
    exit 1
fi

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate venv
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt
pip install pyinstaller

# Build with PyInstaller
echo "Building application..."
pyinstaller ssh_terminal.spec --clean

# Create DMG if create-dmg is available
if command -v create-dmg &> /dev/null; then
    echo "Creating DMG installer..."

    # Remove old DMG if exists
    rm -f "dist/SSHTerminalManager.dmg"

    create-dmg \
        --volname "SSH Terminal Manager" \
        --volicon "src/resources/icons/terminal.icns" \
        --window-pos 200 120 \
        --window-size 600 400 \
        --icon-size 100 \
        --icon "SSH Terminal Manager.app" 150 185 \
        --hide-extension "SSH Terminal Manager.app" \
        --app-drop-link 450 185 \
        "dist/SSHTerminalManager.dmg" \
        "dist/SSH Terminal Manager.app"
else
    echo "create-dmg not found - skipping DMG creation"
    echo "Install with: brew install create-dmg"
fi

echo "========================================"
echo "Build complete!"
echo "Application: dist/SSH Terminal Manager.app"
if [ -f "dist/SSHTerminalManager.dmg" ]; then
    echo "Installer: dist/SSHTerminalManager.dmg"
fi
echo "========================================"
