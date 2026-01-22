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

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ssh-terminal-manager.git
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

## Dependencies

- PyQt6 - GUI framework
- paramiko - SSH client
- pyte - Terminal emulation
- cryptography - Encryption
- keyring - Secure credential storage

## Configuration

Settings are stored in `config/settings.json`. The application creates a SQLite database in `data/connections.db` for storing connection profiles (credentials are encrypted).

## Security

- Passwords are encrypted using AES-256-GCM
- On Windows, the encryption key is protected by DPAPI (tied to your user account)
- On other platforms, a master password is required
- SSH host keys are verified against `data/known_hosts`
- Session activity is logged to `data/audit.log`

## License

MIT License
