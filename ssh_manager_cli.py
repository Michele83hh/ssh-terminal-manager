#!/usr/bin/env python3
"""
SSH Terminal Manager - CLI Version

A lightweight command-line SSH connection manager for Linux/Kali.
Uses the same encrypted credential storage as the GUI version.

Usage:
    python ssh_manager_cli.py              # Interactive menu
    python ssh_manager_cli.py list         # List connections
    python ssh_manager_cli.py connect NAME # Connect to saved connection
    python ssh_manager_cli.py quick HOST   # Quick connect (user@host or host)
"""

import os
import sys
import getpass
import argparse
import signal
import termios
import tty
import select
import threading
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.storage.database import Database, Connection
from src.storage.encryption import EncryptionManager
from src.ssh.session import SSHSession, SSHConfig, HostKeyStatus


class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    BG_BLUE = '\033[44m'
    BG_GREEN = '\033[42m'
    BG_RED = '\033[41m'


def clear_screen():
    """Clear terminal screen."""
    os.system('clear' if os.name != 'nt' else 'cls')


def print_header():
    """Print application header."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}")
    print("  ╔═══════════════════════════════════════════╗")
    print("  ║       SSH Terminal Manager - CLI          ║")
    print("  ╚═══════════════════════════════════════════╝")
    print(f"{Colors.RESET}")


def print_menu(options: list, title: str = "Menu"):
    """Print a numbered menu."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}── {title} ──{Colors.RESET}\n")
    for i, option in enumerate(options, 1):
        print(f"  {Colors.CYAN}[{i}]{Colors.RESET} {option}")
    print(f"  {Colors.DIM}[0] Back / Exit{Colors.RESET}")
    print()


def get_input(prompt: str, default: str = "") -> str:
    """Get user input with optional default."""
    if default:
        prompt = f"{prompt} [{default}]: "
    else:
        prompt = f"{prompt}: "

    result = input(f"{Colors.GREEN}{prompt}{Colors.RESET}").strip()
    return result if result else default


def get_password(prompt: str = "Password") -> str:
    """Get password input (hidden)."""
    return getpass.getpass(f"{Colors.GREEN}{prompt}: {Colors.RESET}")


def confirm(prompt: str) -> bool:
    """Ask for confirmation."""
    response = input(f"{Colors.YELLOW}{prompt} [y/N]: {Colors.RESET}").strip().lower()
    return response in ('y', 'yes')


def print_success(msg: str):
    """Print success message."""
    print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")


def print_error(msg: str):
    """Print error message."""
    print(f"{Colors.RED}[!] {msg}{Colors.RESET}")


def print_warning(msg: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}[*] {msg}{Colors.RESET}")


def print_info(msg: str):
    """Print info message."""
    print(f"{Colors.BLUE}[i] {msg}{Colors.RESET}")


class SSHManagerCLI:
    """CLI interface for SSH Terminal Manager."""

    def __init__(self):
        self.db = Database()
        self.encryption = EncryptionManager(use_dpapi=False, timeout_seconds=0)
        self._running = True
        self._session: SSHSession = None

    def initialize_encryption(self) -> bool:
        """Initialize encryption with master password."""
        salt_path = Path(__file__).parent / "data" / ".salt"

        if salt_path.exists():
            # Existing installation - verify password
            self.encryption.load_salt_from_file(salt_path)
            print_info("Encrypted database found.")

            for attempt in range(3):
                password = get_password("Master Password")
                if not password:
                    return False

                try:
                    self.encryption.initialize_with_password(password, self.encryption.get_salt())
                    # Try to verify by accessing something
                    return True
                except Exception:
                    print_error(f"Wrong password. {2 - attempt} attempts remaining.")

            return False
        else:
            # New installation - create password
            print_info("First run - create a master password for encryption.")
            print_warning("This password protects all saved credentials!")

            while True:
                password = get_password("New Master Password")
                if len(password) < 8:
                    print_error("Password must be at least 8 characters.")
                    continue

                confirm_pw = get_password("Confirm Password")
                if password != confirm_pw:
                    print_error("Passwords don't match.")
                    continue

                break

            salt = self.encryption.initialize_with_password(password)
            salt_path.parent.mkdir(parents=True, exist_ok=True)
            self.encryption.save_salt_to_file(salt_path)
            print_success("Encryption initialized.")
            return True

    def list_connections(self, show_menu: bool = True) -> list:
        """List all saved connections."""
        connections = self.db.get_all_connections()

        if not connections:
            print_warning("No saved connections.")
            return []

        # Group by group_name
        groups = {}
        for conn in connections:
            group = conn.group_name or "Default"
            if group not in groups:
                groups[group] = []
            groups[group].append(conn)

        print(f"\n{Colors.BOLD}Saved Connections:{Colors.RESET}\n")

        idx = 1
        conn_map = {}
        for group_name, conns in sorted(groups.items()):
            print(f"  {Colors.BLUE}[{group_name}]{Colors.RESET}")
            for conn in conns:
                conn_map[idx] = conn
                status = f"{Colors.DIM}(key){Colors.RESET}" if conn.ssh_key_path else ""
                print(f"    {Colors.CYAN}{idx:2}.{Colors.RESET} {conn.name} - {conn.username}@{conn.host}:{conn.port} {status}")
                idx += 1
            print()

        return conn_map

    def add_connection(self):
        """Add a new connection."""
        print(f"\n{Colors.BOLD}Add New Connection{Colors.RESET}\n")

        name = get_input("Connection Name")
        if not name:
            print_error("Name is required.")
            return

        host = get_input("Hostname/IP")
        if not host:
            print_error("Host is required.")
            return

        port = get_input("Port", "22")
        try:
            port = int(port)
        except ValueError:
            port = 22

        username = get_input("Username")
        if not username:
            print_error("Username is required.")
            return

        group = get_input("Group", "Default")

        # Authentication method
        print(f"\n{Colors.BOLD}Authentication:{Colors.RESET}")
        print(f"  {Colors.CYAN}[1]{Colors.RESET} Password")
        print(f"  {Colors.CYAN}[2]{Colors.RESET} SSH Key")
        auth_choice = get_input("Choice", "1")

        encrypted_password = None
        ssh_key_path = None

        if auth_choice == "2":
            ssh_key_path = get_input("SSH Key Path", "~/.ssh/id_rsa")
            ssh_key_path = os.path.expanduser(ssh_key_path)
            if not os.path.exists(ssh_key_path):
                print_warning(f"Key file not found: {ssh_key_path}")
        else:
            password = get_password("Password (leave empty to ask on connect)")
            if password:
                try:
                    encrypted_password = self.encryption.encrypt(password)
                except Exception as e:
                    print_error(f"Encryption failed: {e}")
                    return

        conn = Connection(
            name=name,
            host=host,
            port=port,
            username=username,
            group_name=group,
            encrypted_password=encrypted_password,
            ssh_key_path=ssh_key_path
        )

        try:
            self.db.add_connection(conn)
            print_success(f"Connection '{name}' saved.")
        except Exception as e:
            print_error(f"Failed to save: {e}")

    def edit_connection(self):
        """Edit an existing connection."""
        conn_map = self.list_connections()
        if not conn_map:
            return

        choice = get_input("Edit connection #")
        try:
            idx = int(choice)
            conn = conn_map.get(idx)
            if not conn:
                print_error("Invalid selection.")
                return
        except ValueError:
            print_error("Invalid input.")
            return

        print(f"\n{Colors.BOLD}Edit: {conn.name}{Colors.RESET}")
        print(f"{Colors.DIM}(Press Enter to keep current value){Colors.RESET}\n")

        conn.name = get_input("Name", conn.name)
        conn.host = get_input("Host", conn.host)
        conn.port = int(get_input("Port", str(conn.port)))
        conn.username = get_input("Username", conn.username)
        conn.group_name = get_input("Group", conn.group_name)

        if confirm("Update password?"):
            password = get_password("New Password")
            if password:
                conn.encrypted_password = self.encryption.encrypt(password)

        if confirm("Update SSH key?"):
            key_path = get_input("SSH Key Path")
            conn.ssh_key_path = os.path.expanduser(key_path) if key_path else None

        try:
            self.db.update_connection(conn)
            print_success("Connection updated.")
        except Exception as e:
            print_error(f"Update failed: {e}")

    def delete_connection(self):
        """Delete a connection."""
        conn_map = self.list_connections()
        if not conn_map:
            return

        choice = get_input("Delete connection #")
        try:
            idx = int(choice)
            conn = conn_map.get(idx)
            if not conn:
                print_error("Invalid selection.")
                return
        except ValueError:
            print_error("Invalid input.")
            return

        if confirm(f"Delete '{conn.name}'?"):
            self.db.delete_connection(conn.id)
            print_success("Connection deleted.")

    def connect(self, conn: Connection = None):
        """Connect to an SSH server."""
        if conn is None:
            conn_map = self.list_connections()
            if not conn_map:
                return

            choice = get_input("Connect to #")
            try:
                idx = int(choice)
                conn = conn_map.get(idx)
                if not conn:
                    print_error("Invalid selection.")
                    return
            except ValueError:
                print_error("Invalid input.")
                return

        # Get password if needed
        password = None
        if conn.encrypted_password:
            try:
                password = self.encryption.decrypt(conn.encrypted_password)
            except Exception:
                print_warning("Couldn't decrypt stored password.")
                password = get_password(f"Password for {conn.username}@{conn.host}")
        elif not conn.ssh_key_path:
            password = get_password(f"Password for {conn.username}@{conn.host}")

        self._start_ssh_session(
            host=conn.host,
            port=conn.port,
            username=conn.username,
            password=password,
            key_path=conn.ssh_key_path
        )

        # Update usage stats
        self.db.mark_connection_used(conn.id)

    def quick_connect(self, target: str = None):
        """Quick connect without saving."""
        if target is None:
            target = get_input("Target (user@host or host)")

        if not target:
            return

        # Parse target
        if '@' in target:
            username, host = target.split('@', 1)
        else:
            username = get_input("Username")
            host = target

        # Parse port from host
        port = 22
        if ':' in host:
            host, port_str = host.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                pass

        password = get_password(f"Password for {username}@{host}")

        self._start_ssh_session(
            host=host,
            port=port,
            username=username,
            password=password
        )

    def _host_key_callback(self, hostname: str, port: int, key_type: str,
                           fingerprint: str, status: HostKeyStatus) -> bool:
        """Handle host key verification."""
        if status == HostKeyStatus.CHANGED:
            print_error("=" * 60)
            print_error("WARNING: HOST KEY HAS CHANGED!")
            print_error("This could indicate a man-in-the-middle attack!")
            print_error("=" * 60)
            print(f"  Host: {hostname}:{port}")
            print(f"  Key Type: {key_type}")
            print(f"  Fingerprint: {fingerprint}")
            print()
            return confirm("Accept new key anyway? (DANGEROUS)")
        else:
            print_warning("Unknown host key:")
            print(f"  Host: {hostname}:{port}")
            print(f"  Key Type: {key_type}")
            print(f"  Fingerprint: {fingerprint}")
            print()
            return confirm("Accept and save this key?")

    def _start_ssh_session(self, host: str, port: int, username: str,
                           password: str = None, key_path: str = None):
        """Start an interactive SSH session."""
        config = SSHConfig(
            host=host,
            port=port,
            username=username,
            password=password,
            key_path=key_path,
            timeout=30,
            keepalive_interval=60
        )

        session = SSHSession(config)
        session.on_host_key_verify = self._host_key_callback

        print_info(f"Connecting to {username}@{host}:{port}...")

        if not session.connect():
            print_error("Connection failed.")
            return

        print_success("Connected!")

        # Get terminal size
        try:
            rows, cols = os.get_terminal_size()
        except OSError:
            cols, rows = 80, 24

        if not session.open_shell(cols=cols, rows=rows):
            print_error("Failed to open shell.")
            session.disconnect()
            return

        print_info("Press Ctrl+] to disconnect.\n")

        # Save terminal settings
        old_settings = termios.tcgetattr(sys.stdin)

        try:
            # Set terminal to raw mode
            tty.setraw(sys.stdin.fileno())

            # Data received callback
            def on_data(data: bytes):
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()

            session.on_data = on_data

            # Read input and send to SSH
            while session.is_connected():
                # Check for input
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    char = sys.stdin.read(1)

                    # Ctrl+] to disconnect
                    if char == '\x1d':
                        break

                    session.send(char.encode('utf-8'))

        except Exception as e:
            print_error(f"Session error: {e}")
        finally:
            # Restore terminal settings
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            session.disconnect()
            print(f"\n{Colors.YELLOW}Disconnected.{Colors.RESET}")

    def search_connections(self):
        """Search connections."""
        query = get_input("Search query")
        if not query:
            return

        connections = self.db.search_connections(query)

        if not connections:
            print_warning("No matches found.")
            return

        print(f"\n{Colors.BOLD}Search Results:{Colors.RESET}\n")

        conn_map = {}
        for idx, conn in enumerate(connections, 1):
            conn_map[idx] = conn
            print(f"  {Colors.CYAN}{idx:2}.{Colors.RESET} {conn.name} - {conn.username}@{conn.host}:{conn.port}")

        print()
        choice = get_input("Connect to # (or Enter to cancel)")
        if choice:
            try:
                idx = int(choice)
                conn = conn_map.get(idx)
                if conn:
                    self.connect(conn)
            except ValueError:
                pass

    def import_export_menu(self):
        """Import/Export menu."""
        print_menu([
            "Export connections (JSON)",
            "Import connections (JSON)",
            "Import from OpenSSH config"
        ], "Import/Export")

        choice = get_input("Choice")

        if choice == "1":
            self._export_json()
        elif choice == "2":
            self._import_json()
        elif choice == "3":
            self._import_ssh_config()

    def _export_json(self):
        """Export connections to JSON."""
        path = get_input("Export path", "connections.json")

        connections = self.db.get_all_connections()
        if not connections:
            print_warning("No connections to export.")
            return

        import json
        data = []
        for conn in connections:
            data.append({
                'name': conn.name,
                'host': conn.host,
                'port': conn.port,
                'username': conn.username,
                'group': conn.group_name,
                'ssh_key_path': conn.ssh_key_path
                # Note: Passwords are NOT exported for security
            })

        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

        print_success(f"Exported {len(data)} connections to {path}")
        print_warning("Note: Passwords were not exported for security.")

    def _import_json(self):
        """Import connections from JSON."""
        path = get_input("Import path", "connections.json")

        if not os.path.exists(path):
            print_error(f"File not found: {path}")
            return

        import json
        with open(path, 'r') as f:
            data = json.load(f)

        count = 0
        for item in data:
            conn = Connection(
                name=item.get('name', ''),
                host=item.get('host', ''),
                port=item.get('port', 22),
                username=item.get('username', ''),
                group_name=item.get('group', 'Imported'),
                ssh_key_path=item.get('ssh_key_path')
            )

            if conn.name and conn.host and conn.username:
                try:
                    self.db.add_connection(conn)
                    count += 1
                except Exception:
                    pass

        print_success(f"Imported {count} connections.")

    def _import_ssh_config(self):
        """Import from ~/.ssh/config."""
        path = get_input("SSH config path", "~/.ssh/config")
        path = os.path.expanduser(path)

        if not os.path.exists(path):
            print_error(f"File not found: {path}")
            return

        count = 0
        current = {}

        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if line.lower().startswith('host '):
                    if current.get('host'):
                        self._save_ssh_config_entry(current)
                        count += 1
                    current = {'name': line.split(None, 1)[1]}
                elif '=' in line or ' ' in line:
                    parts = line.replace('=', ' ').split(None, 1)
                    if len(parts) == 2:
                        key, value = parts
                        key = key.lower()
                        if key == 'hostname':
                            current['host'] = value
                        elif key == 'port':
                            current['port'] = int(value)
                        elif key == 'user':
                            current['username'] = value
                        elif key == 'identityfile':
                            current['ssh_key_path'] = os.path.expanduser(value)

        if current.get('host'):
            self._save_ssh_config_entry(current)
            count += 1

        print_success(f"Imported {count} connections from SSH config.")

    def _save_ssh_config_entry(self, entry: dict):
        """Save a parsed SSH config entry."""
        if not entry.get('host'):
            return

        conn = Connection(
            name=entry.get('name', entry['host']),
            host=entry['host'],
            port=entry.get('port', 22),
            username=entry.get('username', os.environ.get('USER', 'root')),
            group_name='SSH Config',
            ssh_key_path=entry.get('ssh_key_path')
        )

        try:
            self.db.add_connection(conn)
        except Exception:
            pass

    def main_menu(self):
        """Main interactive menu."""
        while self._running:
            clear_screen()
            print_header()

            print_menu([
                "List Connections",
                "Connect",
                "Quick Connect",
                "Add Connection",
                "Edit Connection",
                "Delete Connection",
                "Search",
                "Import/Export"
            ], "Main Menu")

            choice = get_input("Choice")

            if choice == "0" or choice.lower() in ('q', 'quit', 'exit'):
                self._running = False
            elif choice == "1":
                self.list_connections()
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
            elif choice == "2":
                self.connect()
            elif choice == "3":
                self.quick_connect()
            elif choice == "4":
                self.add_connection()
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
            elif choice == "5":
                self.edit_connection()
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
            elif choice == "6":
                self.delete_connection()
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
            elif choice == "7":
                self.search_connections()
            elif choice == "8":
                self.import_export_menu()
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

    def run(self, args):
        """Run CLI with parsed arguments."""
        # Initialize encryption
        if not self.initialize_encryption():
            print_error("Encryption initialization failed.")
            return 1

        # Handle command-line arguments
        if args.command == 'list':
            self.list_connections()
            return 0

        elif args.command == 'connect':
            if args.name:
                connections = self.db.search_connections(args.name)
                if connections:
                    self.connect(connections[0])
                else:
                    print_error(f"Connection not found: {args.name}")
                    return 1
            else:
                self.connect()
            return 0

        elif args.command == 'quick':
            self.quick_connect(args.target)
            return 0

        elif args.command == 'add':
            self.add_connection()
            return 0

        else:
            # Interactive mode
            self.main_menu()
            return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='SSH Terminal Manager - CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    Interactive menu
  %(prog)s list               List all connections
  %(prog)s connect webserver  Connect to 'webserver'
  %(prog)s quick root@10.0.0.1  Quick connect
  %(prog)s add                Add new connection
        """
    )

    subparsers = parser.add_subparsers(dest='command')

    # list command
    subparsers.add_parser('list', help='List all connections')

    # connect command
    connect_parser = subparsers.add_parser('connect', help='Connect to saved connection')
    connect_parser.add_argument('name', nargs='?', help='Connection name')

    # quick command
    quick_parser = subparsers.add_parser('quick', help='Quick connect (user@host)')
    quick_parser.add_argument('target', nargs='?', help='Target (user@host or host)')

    # add command
    subparsers.add_parser('add', help='Add new connection')

    args = parser.parse_args()

    # Check if running on a proper terminal
    if not sys.stdin.isatty():
        print("Error: Must run in interactive terminal.")
        return 1

    cli = SSHManagerCLI()

    try:
        return cli.run(args)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted.{Colors.RESET}")
        return 130


if __name__ == '__main__':
    sys.exit(main())
