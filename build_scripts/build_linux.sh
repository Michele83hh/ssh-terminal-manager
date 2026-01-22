#!/bin/bash
# Linux Build Script for SSH Terminal Manager
# Creates AppImage and .deb package

set -e

echo "========================================"
echo "SSH Terminal Manager - Linux Build"
echo "========================================"

# Check if running on Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "ERROR: This script must be run on Linux"
    exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

VERSION="1.0.0"
APP_NAME="ssh-terminal-manager"

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

# Create AppDir structure
echo "Creating AppImage..."
APPDIR="dist/SSHTerminalManager.AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# Copy files
cp -r dist/SSHTerminalManager/* "$APPDIR/usr/bin/"

# Create desktop file
cat > "$APPDIR/usr/share/applications/ssh-terminal-manager.desktop" << EOF
[Desktop Entry]
Type=Application
Name=SSH Terminal Manager
Comment=SSH Terminal Manager with encrypted credentials
Exec=SSHTerminalManager
Icon=ssh-terminal-manager
Categories=Network;RemoteAccess;
Terminal=false
EOF

# Copy desktop file to AppDir root
cp "$APPDIR/usr/share/applications/ssh-terminal-manager.desktop" "$APPDIR/"

# Create icon (placeholder - ideally convert SVG to PNG)
if command -v convert &> /dev/null; then
    convert -background none -size 256x256 src/resources/icons/terminal.svg "$APPDIR/usr/share/icons/hicolor/256x256/apps/ssh-terminal-manager.png"
    cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/ssh-terminal-manager.png" "$APPDIR/ssh-terminal-manager.png"
else
    echo "ImageMagick not found - using placeholder icon"
    # Create a simple placeholder
    cp src/resources/icons/terminal.svg "$APPDIR/ssh-terminal-manager.svg"
fi

# Create AppRun
cat > "$APPDIR/AppRun" << 'EOF'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin:${PATH}"
export LD_LIBRARY_PATH="${HERE}/usr/lib:${LD_LIBRARY_PATH}"
exec "${HERE}/usr/bin/SSHTerminalManager" "$@"
EOF
chmod +x "$APPDIR/AppRun"

# Download appimagetool if not present
if [ ! -f "build_scripts/appimagetool-x86_64.AppImage" ]; then
    echo "Downloading appimagetool..."
    wget -q "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage" \
        -O "build_scripts/appimagetool-x86_64.AppImage"
    chmod +x "build_scripts/appimagetool-x86_64.AppImage"
fi

# Create AppImage
ARCH=x86_64 ./build_scripts/appimagetool-x86_64.AppImage "$APPDIR" "dist/SSHTerminalManager-${VERSION}-x86_64.AppImage"

# Create .deb package
echo "Creating .deb package..."
DEB_DIR="dist/deb-build"
rm -rf "$DEB_DIR"
mkdir -p "$DEB_DIR/DEBIAN"
mkdir -p "$DEB_DIR/usr/bin"
mkdir -p "$DEB_DIR/usr/share/applications"
mkdir -p "$DEB_DIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$DEB_DIR/opt/ssh-terminal-manager"

# Copy application
cp -r dist/SSHTerminalManager/* "$DEB_DIR/opt/ssh-terminal-manager/"

# Create launcher script
cat > "$DEB_DIR/usr/bin/ssh-terminal-manager" << 'EOF'
#!/bin/bash
exec /opt/ssh-terminal-manager/SSHTerminalManager "$@"
EOF
chmod +x "$DEB_DIR/usr/bin/ssh-terminal-manager"

# Copy desktop file
cp "$APPDIR/usr/share/applications/ssh-terminal-manager.desktop" "$DEB_DIR/usr/share/applications/"

# Copy icon
if [ -f "$APPDIR/usr/share/icons/hicolor/256x256/apps/ssh-terminal-manager.png" ]; then
    cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/ssh-terminal-manager.png" \
       "$DEB_DIR/usr/share/icons/hicolor/256x256/apps/"
fi

# Calculate installed size
INSTALLED_SIZE=$(du -s "$DEB_DIR" | cut -f1)

# Create control file
cat > "$DEB_DIR/DEBIAN/control" << EOF
Package: ssh-terminal-manager
Version: ${VERSION}
Section: net
Priority: optional
Architecture: amd64
Installed-Size: ${INSTALLED_SIZE}
Depends: libxcb-xinerama0, libxcb-cursor0
Maintainer: SSH Terminal Manager <support@example.com>
Description: SSH Terminal Manager
 A PyQt6-based SSH terminal manager with encrypted credential storage,
 multiple tabbed sessions, and a modern dark theme interface.
Homepage: https://github.com/Michele83hh/ssh-terminal-manager
EOF

# Build .deb
dpkg-deb --build "$DEB_DIR" "dist/${APP_NAME}_${VERSION}_amd64.deb"

echo "========================================"
echo "Build complete!"
echo "AppImage: dist/SSHTerminalManager-${VERSION}-x86_64.AppImage"
echo "Deb Package: dist/${APP_NAME}_${VERSION}_amd64.deb"
echo "========================================"
