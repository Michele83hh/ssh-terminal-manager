"""
SQLite database layer for SSH connections storage.

Security: Uses parameterized queries to prevent SQL injection.
Input validation is applied for defense in depth.
"""
import sqlite3
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, List
from datetime import datetime

# Import validation module directly to avoid circular import through __init__
from ..utils import validation as _validation


@dataclass
class Connection:
    """Represents an SSH connection configuration."""
    id: Optional[int] = None
    name: str = ""
    host: str = ""
    port: int = 22
    username: str = ""
    # Credential storage mode: 'local' or 'authentik'
    credential_mode: str = "local"
    # Encrypted password (only used if credential_mode is 'local')
    encrypted_password: Optional[str] = None
    # SSH key path (optional)
    ssh_key_path: Optional[str] = None
    # Group/folder for organization
    group_name: str = "Default"
    # Terminal settings (stored as JSON)
    terminal_settings: dict = field(default_factory=dict)
    # Connection settings
    keepalive_interval: int = 60
    timeout: int = 30
    # Metadata
    created_at: Optional[str] = None
    last_used: Optional[str] = None
    use_count: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary for database storage."""
        return asdict(self)

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> 'Connection':
        """Create Connection from database row."""
        data = dict(row)
        if data.get('terminal_settings'):
            data['terminal_settings'] = json.loads(data['terminal_settings'])
        else:
            data['terminal_settings'] = {}
        return cls(**data)


@dataclass
class Group:
    """Represents a connection group/folder."""
    id: Optional[int] = None
    name: str = ""
    parent_id: Optional[int] = None
    order_index: int = 0
    expanded: bool = True


class Database:
    """SQLite database manager for connections."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = Path(__file__).parent.parent.parent / "data" / "connections.db"
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
        self._secure_database_file()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with row factory."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_database(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Connections table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER DEFAULT 22,
                    username TEXT NOT NULL,
                    credential_mode TEXT DEFAULT 'local',
                    encrypted_password TEXT,
                    ssh_key_path TEXT,
                    group_name TEXT DEFAULT 'Default',
                    terminal_settings TEXT,
                    keepalive_interval INTEGER DEFAULT 60,
                    timeout INTEGER DEFAULT 30,
                    created_at TEXT,
                    last_used TEXT,
                    use_count INTEGER DEFAULT 0
                )
            ''')

            # Groups table for folder structure
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    parent_id INTEGER,
                    order_index INTEGER DEFAULT 0,
                    expanded INTEGER DEFAULT 1,
                    FOREIGN KEY (parent_id) REFERENCES groups(id)
                )
            ''')

            # Insert default group if not exists
            cursor.execute('''
                INSERT OR IGNORE INTO groups (name, order_index)
                VALUES ('Default', 0)
            ''')

            conn.commit()

    def _secure_database_file(self):
        """
        Set secure permissions on database file (user-only access).

        Note: This is a best-effort security enhancement. If it fails,
        the application continues to work normally.
        """
        try:
            from ..utils.file_security import secure_file_permissions, secure_directory_permissions
            # Secure the data directory (non-blocking)
            try:
                secure_directory_permissions(self.db_path.parent)
            except Exception:
                pass
            # Secure the database file (non-blocking)
            try:
                if self.db_path.exists():
                    secure_file_permissions(self.db_path)
            except Exception:
                pass
        except ImportError:
            pass  # file_security module not available
        except Exception:
            pass  # Any other error - continue without secure permissions

    # Connection CRUD operations

    def add_connection(self, conn_data: Connection) -> int:
        """
        Add a new connection. Returns the new connection ID.

        Validates input data before inserting.
        """
        # Validate inputs for security
        conn_data.name = _validation.validate_connection_name(conn_data.name)
        conn_data.host = _validation.validate_hostname(conn_data.host)
        conn_data.port = _validation.validate_port(conn_data.port)
        conn_data.username = _validation.validate_username(conn_data.username)
        conn_data.group_name = _validation.validate_group_name(conn_data.group_name)

        conn_data.created_at = datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO connections (
                    name, host, port, username, credential_mode,
                    encrypted_password, ssh_key_path, group_name,
                    terminal_settings, keepalive_interval, timeout,
                    created_at, last_used, use_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                conn_data.name, conn_data.host, conn_data.port,
                conn_data.username, conn_data.credential_mode,
                conn_data.encrypted_password, conn_data.ssh_key_path,
                conn_data.group_name, json.dumps(conn_data.terminal_settings),
                conn_data.keepalive_interval, conn_data.timeout,
                conn_data.created_at, conn_data.last_used, conn_data.use_count
            ))
            conn.commit()
            return cursor.lastrowid

    def update_connection(self, conn_data: Connection) -> bool:
        """
        Update an existing connection.

        Validates input data before updating.
        """
        # Validate inputs for security
        conn_data.name = _validation.validate_connection_name(conn_data.name)
        conn_data.host = _validation.validate_hostname(conn_data.host)
        conn_data.port = _validation.validate_port(conn_data.port)
        conn_data.username = _validation.validate_username(conn_data.username)
        conn_data.group_name = _validation.validate_group_name(conn_data.group_name)

        if conn_data.id is None:
            return False
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE connections SET
                    name = ?, host = ?, port = ?, username = ?,
                    credential_mode = ?, encrypted_password = ?,
                    ssh_key_path = ?, group_name = ?, terminal_settings = ?,
                    keepalive_interval = ?, timeout = ?, last_used = ?, use_count = ?
                WHERE id = ?
            ''', (
                conn_data.name, conn_data.host, conn_data.port,
                conn_data.username, conn_data.credential_mode,
                conn_data.encrypted_password, conn_data.ssh_key_path,
                conn_data.group_name, json.dumps(conn_data.terminal_settings),
                conn_data.keepalive_interval, conn_data.timeout,
                conn_data.last_used, conn_data.use_count, conn_data.id
            ))
            conn.commit()
            return cursor.rowcount > 0

    def delete_connection(self, connection_id: int) -> bool:
        """Delete a connection by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM connections WHERE id = ?', (connection_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_connection(self, connection_id: int) -> Optional[Connection]:
        """Get a single connection by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM connections WHERE id = ?', (connection_id,))
            row = cursor.fetchone()
            if row:
                return Connection.from_row(row)
            return None

    def get_all_connections(self) -> List[Connection]:
        """Get all connections."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM connections ORDER BY group_name, name')
            return [Connection.from_row(row) for row in cursor.fetchall()]

    def get_connections_by_group(self, group_name: str) -> List[Connection]:
        """Get connections in a specific group."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM connections WHERE group_name = ? ORDER BY name',
                (group_name,)
            )
            return [Connection.from_row(row) for row in cursor.fetchall()]

    def mark_connection_used(self, connection_id: int):
        """Update last_used timestamp and increment use_count."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE connections SET
                    last_used = ?,
                    use_count = use_count + 1
                WHERE id = ?
            ''', (datetime.now().isoformat(), connection_id))
            conn.commit()

    def search_connections(self, query: str) -> List[Connection]:
        """Search connections by name or host."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            search_term = f'%{query}%'
            cursor.execute('''
                SELECT * FROM connections
                WHERE name LIKE ? OR host LIKE ? OR username LIKE ?
                ORDER BY use_count DESC, name
            ''', (search_term, search_term, search_term))
            return [Connection.from_row(row) for row in cursor.fetchall()]

    # Group operations

    def add_group(self, group: Group) -> int:
        """Add a new group. Returns the new group ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO groups (name, parent_id, order_index, expanded)
                VALUES (?, ?, ?, ?)
            ''', (group.name, group.parent_id, group.order_index, int(group.expanded)))
            conn.commit()
            return cursor.lastrowid

    def get_all_groups(self) -> List[Group]:
        """Get all groups."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM groups ORDER BY order_index, name')
            groups = []
            for row in cursor.fetchall():
                groups.append(Group(
                    id=row['id'],
                    name=row['name'],
                    parent_id=row['parent_id'],
                    order_index=row['order_index'],
                    expanded=bool(row['expanded'])
                ))
            return groups

    def delete_group(self, group_id: int) -> bool:
        """Delete a group by ID. Connections in this group move to Default."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Get group name
            cursor.execute('SELECT name FROM groups WHERE id = ?', (group_id,))
            row = cursor.fetchone()
            if not row or row['name'] == 'Default':
                return False

            group_name = row['name']
            # Move connections to Default group
            cursor.execute(
                'UPDATE connections SET group_name = ? WHERE group_name = ?',
                ('Default', group_name)
            )
            # Delete group
            cursor.execute('DELETE FROM groups WHERE id = ?', (group_id,))
            conn.commit()
            return True

    def rename_group(self, old_name: str, new_name: str) -> bool:
        """Rename a group and update all connections."""
        if old_name == 'Default':
            return False
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE groups SET name = ? WHERE name = ?', (new_name, old_name))
            cursor.execute(
                'UPDATE connections SET group_name = ? WHERE group_name = ?',
                (new_name, old_name)
            )
            conn.commit()
            return True
