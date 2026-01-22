# SSH Terminal Manager

A modern SSH terminal manager built with PyQt6, featuring tabbed sessions, connection management, and a dark theme interface.

## Features

- **Multiple SSH Sessions**: Open multiple SSH connections in tabs
- **Detachable Terminals**: Detach tabs to separate windows and reattach them
- **Connection Management**: Save and organize connections in groups/folders
- **Encrypted Credentials**: Secure password storage using AES-256-GCM encryption with Windows DPAPI or master password
- **Terminal Emulation**: Full VT100/xterm terminal emulation via pyte
- **Customizable Appearance**: Configurable fonts, colors, and cursor styles
- **Session Timeout**: Automatic disconnection after inactivity
- **Audit Logging**: Track connection events for security
- **Host Key Verification**: SSH host key checking with known_hosts support

## Requirements

- Python 3.10+
- Windows (for DPAPI support) or Linux/macOS (with master password)

## Installation

### GUI Version (Windows/Linux/macOS)

1. Clone the repository:
   ```bash
   git clone https://github.com/Michele83hh/ssh-terminal-manager.git
   cd ssh-terminal-manager
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python main.py
   ```

### CLI Version (Kali Linux / Terminal-only)

For headless systems or when you prefer a terminal interface:

1. Clone the repository:
   ```bash
   git clone https://github.com/Michele83hh/ssh-terminal-manager.git
   cd ssh-terminal-manager
   ```

2. Install minimal dependencies:
   ```bash
   pip install -r requirements-cli.txt
   ```

3. Run the CLI:
   ```bash
   python ssh_manager_cli.py
   ```

#### CLI Commands

```bash
# Interactive menu
python ssh_manager_cli.py

# List all saved connections
python ssh_manager_cli.py list

# Connect to a saved connection
python ssh_manager_cli.py connect webserver

# Quick connect (without saving)
python ssh_manager_cli.py quick root@10.0.0.1
python ssh_manager_cli.py quick user@host:2222

# Add a new connection
python ssh_manager_cli.py add
```

#### CLI Features

- Same encrypted credential storage as GUI version
- Import from `~/.ssh/config`
- Host key verification with known_hosts
- Ctrl+] to disconnect from session

## Dependencies

- PyQt6 - GUI framework
- paramiko - SSH client
- pyte - Terminal emulation
- cryptography - Encryption
- keyring - Secure credential storage

## Configuration

Settings are stored in `config/settings.json`. The application creates a SQLite database in `data/connections.db` for storing connection profiles (credentials are encrypted).

## Building Installers

### Quick Build (All Platforms)

```bash
python build_scripts/build.py
```

This creates a standalone executable in `dist/SSHTerminalManager/`.

### Windows Installer (.exe)

Requirements:
- [Inno Setup 6](https://jrsoftware.org/isdl.php) (optional, for installer)

```bash
# Option 1: Using batch script
build_scripts\build_windows.bat

# Option 2: Using Python script
python build_scripts\build.py
```

Output:
- `dist/SSHTerminalManager/` - Standalone executable
- `dist/SSHTerminalManager_Setup_1.0.0.exe` - Installer (if Inno Setup installed)

### macOS (.app / .dmg)

Requirements:
- [create-dmg](https://github.com/create-dmg/create-dmg) (optional, for DMG)

```bash
chmod +x build_scripts/build_macos.sh
./build_scripts/build_macos.sh
```

Output:
- `dist/SSH Terminal Manager.app` - Application bundle
- `dist/SSHTerminalManager.dmg` - DMG installer (if create-dmg installed)

### Linux (AppImage / .deb)

Requirements:
- `dpkg-deb` (for .deb package)
- ImageMagick (optional, for icon conversion)

```bash
chmod +x build_scripts/build_linux.sh
./build_scripts/build_linux.sh
```

Output:
- `dist/SSHTerminalManager-1.0.0-x86_64.AppImage` - AppImage
- `dist/ssh-terminal-manager_1.0.0_amd64.deb` - Debian package

## Security

- Passwords are encrypted using AES-256-GCM
- On Windows, the encryption key is protected by DPAPI (tied to your user account)
- On other platforms, a master password is required
- SSH host keys are verified against `data/known_hosts`
- Session activity is logged to `data/audit.log`

## License

MIT License
