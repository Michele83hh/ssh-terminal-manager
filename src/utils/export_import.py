"""
Export and import functionality for connections.
Supports JSON, CSV, and Putty session import.
"""
import json
import csv
import re
from pathlib import Path
from typing import List, Optional
from dataclasses import asdict

from PyQt6.QtWidgets import QFileDialog, QMessageBox, QWidget

from ..storage.database import Database, Connection


class ExportImport:
    """Handles export and import of SSH connections."""

    @staticmethod
    def export_to_json(connections: List[Connection], path: Path):
        """Export connections to JSON file."""
        data = {
            'version': '1.0',
            'connections': []
        }

        for conn in connections:
            conn_data = asdict(conn)
            # Don't export encrypted passwords
            conn_data.pop('encrypted_password', None)
            conn_data.pop('id', None)
            data['connections'].append(conn_data)

        path.write_text(json.dumps(data, indent=2), encoding='utf-8')

    @staticmethod
    def import_from_json(path: Path) -> List[Connection]:
        """Import connections from JSON file."""
        data = json.loads(path.read_text(encoding='utf-8'))

        connections = []
        for conn_data in data.get('connections', []):
            conn = Connection(
                name=conn_data.get('name', ''),
                host=conn_data.get('host', ''),
                port=conn_data.get('port', 22),
                username=conn_data.get('username', ''),
                group_name=conn_data.get('group_name', 'Imported'),
                ssh_key_path=conn_data.get('ssh_key_path'),
                keepalive_interval=conn_data.get('keepalive_interval', 60),
                timeout=conn_data.get('timeout', 30),
                terminal_settings=conn_data.get('terminal_settings', {}),
            )
            connections.append(conn)

        return connections

    @staticmethod
    def export_to_csv(connections: List[Connection], path: Path):
        """Export connections to CSV file."""
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Name', 'Host', 'Port', 'Username', 'Group',
                'SSH Key Path', 'Keepalive', 'Timeout'
            ])

            for conn in connections:
                writer.writerow([
                    conn.name,
                    conn.host,
                    conn.port,
                    conn.username,
                    conn.group_name,
                    conn.ssh_key_path or '',
                    conn.keepalive_interval,
                    conn.timeout
                ])

    @staticmethod
    def import_from_csv(path: Path) -> List[Connection]:
        """Import connections from CSV file."""
        connections = []

        with open(path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                conn = Connection(
                    name=row.get('Name', ''),
                    host=row.get('Host', ''),
                    port=int(row.get('Port', 22)),
                    username=row.get('Username', ''),
                    group_name=row.get('Group', 'Imported'),
                    ssh_key_path=row.get('SSH Key Path') or None,
                    keepalive_interval=int(row.get('Keepalive', 60)),
                    timeout=int(row.get('Timeout', 30)),
                )
                connections.append(conn)

        return connections

    @staticmethod
    def import_from_putty_registry() -> List[Connection]:
        """
        Import sessions from Putty registry (Windows only).

        Note: This reads from HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions
        """
        connections = []

        try:
            import winreg

            sessions_key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\SimonTatham\PuTTY\Sessions"
            )

            i = 0
            while True:
                try:
                    session_name = winreg.EnumKey(sessions_key, i)
                    i += 1

                    # Decode URL-encoded session name
                    import urllib.parse
                    decoded_name = urllib.parse.unquote(session_name)

                    # Open session key
                    session_key = winreg.OpenKey(sessions_key, session_name)

                    # Read values
                    try:
                        host, _ = winreg.QueryValueEx(session_key, "HostName")
                        port, _ = winreg.QueryValueEx(session_key, "PortNumber")
                        username, _ = winreg.QueryValueEx(session_key, "UserName")
                        protocol, _ = winreg.QueryValueEx(session_key, "Protocol")

                        # Only import SSH sessions
                        if protocol == "ssh" and host:
                            conn = Connection(
                                name=decoded_name,
                                host=host,
                                port=port,
                                username=username or "",
                                group_name="Putty Import",
                            )

                            # Try to get key file
                            try:
                                key_file, _ = winreg.QueryValueEx(
                                    session_key, "PublicKeyFile"
                                )
                                if key_file:
                                    conn.ssh_key_path = key_file
                            except WindowsError:
                                pass

                            connections.append(conn)

                    except WindowsError:
                        pass
                    finally:
                        winreg.CloseKey(session_key)

                except OSError:
                    break

            winreg.CloseKey(sessions_key)

        except ImportError:
            # Not on Windows
            pass
        except Exception:
            pass

        return connections

    @staticmethod
    def import_from_openssh_config(path: Optional[Path] = None) -> List[Connection]:
        """
        Import from OpenSSH config file (~/.ssh/config).
        """
        if path is None:
            path = Path.home() / ".ssh" / "config"

        if not path.exists():
            return []

        connections = []
        current_host = None
        current_data = {}

        for line in path.read_text().splitlines():
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Parse key-value pairs
            match = re.match(r'^(\S+)\s+(.+)$', line)
            if not match:
                continue

            key, value = match.groups()
            key = key.lower()

            if key == 'host':
                # Save previous host
                if current_host and current_data.get('hostname'):
                    conn = Connection(
                        name=current_host,
                        host=current_data.get('hostname', ''),
                        port=int(current_data.get('port', 22)),
                        username=current_data.get('user', ''),
                        ssh_key_path=current_data.get('identityfile'),
                        group_name="SSH Config Import",
                    )
                    connections.append(conn)

                # Start new host (skip wildcards)
                if '*' not in value and '?' not in value:
                    current_host = value
                    current_data = {}
                else:
                    current_host = None

            elif current_host:
                current_data[key] = value

        # Don't forget last host
        if current_host and current_data.get('hostname'):
            conn = Connection(
                name=current_host,
                host=current_data.get('hostname', ''),
                port=int(current_data.get('port', 22)),
                username=current_data.get('user', ''),
                ssh_key_path=current_data.get('identityfile'),
                group_name="SSH Config Import",
            )
            connections.append(conn)

        return connections

    @staticmethod
    def export_dialog(parent: QWidget, database: Database):
        """Show export dialog and export connections."""
        connections = database.get_all_connections()

        if not connections:
            QMessageBox.information(parent, "Export", "No connections to export")
            return

        file_path, file_filter = QFileDialog.getSaveFileName(
            parent,
            "Export Connections",
            "connections.json",
            "JSON Files (*.json);;CSV Files (*.csv)"
        )

        if not file_path:
            return

        path = Path(file_path)

        try:
            if file_filter.startswith("JSON") or path.suffix.lower() == '.json':
                ExportImport.export_to_json(connections, path)
            else:
                ExportImport.export_to_csv(connections, path)

            QMessageBox.information(
                parent,
                "Export Complete",
                f"Exported {len(connections)} connections to {path.name}"
            )

        except Exception as e:
            QMessageBox.critical(parent, "Export Failed", str(e))

    @staticmethod
    def import_dialog(parent: QWidget, database: Database):
        """Show import dialog and import connections."""
        file_path, file_filter = QFileDialog.getOpenFileName(
            parent,
            "Import Connections",
            "",
            "JSON Files (*.json);;CSV Files (*.csv);;SSH Config (config);;All Files (*)"
        )

        if not file_path:
            return

        path = Path(file_path)
        connections = []

        try:
            if path.suffix.lower() == '.json':
                connections = ExportImport.import_from_json(path)
            elif path.suffix.lower() == '.csv':
                connections = ExportImport.import_from_csv(path)
            elif path.name == 'config':
                connections = ExportImport.import_from_openssh_config(path)
            else:
                # Try JSON first, then CSV
                try:
                    connections = ExportImport.import_from_json(path)
                except Exception:
                    connections = ExportImport.import_from_csv(path)

            if not connections:
                QMessageBox.warning(parent, "Import", "No connections found in file")
                return

            # Add connections to database
            imported = 0
            for conn in connections:
                try:
                    database.add_connection(conn)
                    imported += 1
                except Exception:
                    pass

            QMessageBox.information(
                parent,
                "Import Complete",
                f"Imported {imported} connections"
            )

        except Exception as e:
            QMessageBox.critical(parent, "Import Failed", str(e))

    @staticmethod
    def import_putty_dialog(parent: QWidget, database: Database):
        """Import from Putty registry."""
        connections = ExportImport.import_from_putty_registry()

        if not connections:
            QMessageBox.warning(
                parent,
                "Putty Import",
                "No Putty SSH sessions found in registry"
            )
            return

        result = QMessageBox.question(
            parent,
            "Import Putty Sessions",
            f"Found {len(connections)} Putty SSH sessions. Import them?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if result != QMessageBox.StandardButton.Yes:
            return

        imported = 0
        for conn in connections:
            try:
                database.add_connection(conn)
                imported += 1
            except Exception:
                pass

        QMessageBox.information(
            parent,
            "Import Complete",
            f"Imported {imported} Putty sessions"
        )
