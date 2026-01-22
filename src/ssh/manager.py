"""
Connection manager for handling multiple SSH sessions.

Security features:
- Host key verification callback for MITM protection
- Credential encryption
- Audit logging of all connection events
"""
from typing import Dict, Optional, Callable
from dataclasses import dataclass

from .session import SSHSession, SSHConfig, HostKeyStatus
from ..storage.database import Database, Connection
from ..storage.encryption import EncryptionManager
from ..utils.audit_log import AuditLogger, AuditEventType


@dataclass
class ActiveSession:
    """Represents an active SSH session with metadata."""
    session: SSHSession
    connection: Connection
    window_id: Optional[int] = None


class ConnectionManager:
    """
    Manages SSH connections and active sessions.

    Provides:
    - Session lifecycle management
    - Credential resolution (local encrypted or Authentik)
    - Active session tracking
    - Host key verification (MITM protection)
    """

    def __init__(self, database: Database, encryption: EncryptionManager):
        self.database = database
        self.encryption = encryption
        self._active_sessions: Dict[int, ActiveSession] = {}
        self._session_counter = 0
        self._last_error: Optional[str] = None
        self._audit = AuditLogger.get_instance()

        # Callbacks
        self.on_session_start: Optional[Callable[[int, ActiveSession], None]] = None
        self.on_session_end: Optional[Callable[[int, str], None]] = None

        # Host key verification callback - UI should implement this
        # Args: (hostname, port, key_type, fingerprint, status: HostKeyStatus)
        # Returns: True to accept the key, False to reject
        self.on_host_key_verify: Optional[Callable[[str, int, str, str, HostKeyStatus], bool]] = None

    def get_last_error(self) -> Optional[str]:
        """Get the last error message from a failed operation."""
        return self._last_error

    def get_connections(self):
        """Get all saved connections."""
        return self.database.get_all_connections()

    def get_groups(self):
        """Get all groups."""
        return self.database.get_all_groups()

    def save_connection(self, connection: Connection, password: Optional[str] = None) -> int:
        """
        Save a connection to the database.

        Args:
            connection: Connection to save
            password: Optional password to encrypt and store

        Returns:
            Connection ID
        """
        if password and connection.credential_mode == 'local':
            if self.encryption.is_initialized():
                connection.encrypted_password = self.encryption.encrypt(password)

        if connection.id is None:
            return self.database.add_connection(connection)
        else:
            self.database.update_connection(connection)
            return connection.id

    def delete_connection(self, connection_id: int) -> bool:
        """Delete a connection."""
        # Close any active session for this connection
        for session_id, active in list(self._active_sessions.items()):
            if active.connection.id == connection_id:
                self.close_session(session_id)

        return self.database.delete_connection(connection_id)

    def get_password(self, connection: Connection) -> Optional[str]:
        """
        Get decrypted password for a connection.

        Args:
            connection: Connection to get password for

        Returns:
            Decrypted password or None
        """
        if connection.credential_mode == 'local' and connection.encrypted_password:
            if self.encryption.is_initialized():
                try:
                    return self.encryption.decrypt(connection.encrypted_password)
                except Exception:
                    return None
        return None

    def start_session(
        self,
        connection: Connection,
        password: Optional[str] = None
    ) -> Optional[int]:
        """
        Start a new SSH session.

        Args:
            connection: Connection configuration
            password: Optional password (overrides stored password)

        Returns:
            Session ID if successful, None otherwise
        """
        # Resolve password
        if password is None:
            password = self.get_password(connection)

        # Create SSH config
        config = SSHConfig(
            host=connection.host,
            port=connection.port,
            username=connection.username,
            password=password,
            key_path=connection.ssh_key_path,
            timeout=connection.timeout,
            keepalive_interval=connection.keepalive_interval
        )

        # Create session
        session = SSHSession(config)

        # Setup host key verification callback
        session.on_host_key_verify = self.on_host_key_verify

        # Setup error handler to capture error messages
        self._last_error = None

        def on_error(message: str):
            self._last_error = message

        session.on_error = on_error

        # Setup disconnect handler (session_id will be set after connect)
        session_id = None  # Placeholder, set after successful connect

        def on_disconnect(reason: str):
            if session_id is not None:
                self._handle_session_disconnect(session_id, reason)

        session.on_disconnect = on_disconnect

        # Audit: Log connection attempt
        self._audit.log_connection_attempt(
            host=connection.host,
            port=connection.port,
            username=connection.username
        )

        # Connect (may prompt for host key verification)
        if not session.connect():
            # Audit: Log connection failure
            self._audit.log_connection_failed(
                host=connection.host,
                port=connection.port,
                username=connection.username,
                error=self._last_error or "Unknown error"
            )
            return None

        # Get terminal type from connection settings
        term_type = connection.terminal_settings.get('term_type', 'xterm-256color') if connection.terminal_settings else 'xterm-256color'

        # Open shell with terminal type
        if not session.open_shell(term_type=term_type):
            if self._last_error is None:
                self._last_error = "Failed to open shell"
            # Audit: Log shell failure
            self._audit.log_connection_failed(
                host=connection.host,
                port=connection.port,
                username=connection.username,
                error=self._last_error
            )
            session.disconnect()
            return None

        # Track session
        self._session_counter += 1
        session_id = self._session_counter

        active_session = ActiveSession(
            session=session,
            connection=connection
        )
        self._active_sessions[session_id] = active_session

        # Audit: Log successful connection
        self._audit.log_connection_success(
            host=connection.host,
            port=connection.port,
            username=connection.username
        )

        # Update connection usage stats
        if connection.id:
            self.database.mark_connection_used(connection.id)

        # Notify
        if self.on_session_start:
            self.on_session_start(session_id, active_session)

        return session_id

    def close_session(self, session_id: int) -> bool:
        """
        Close an active session.

        Args:
            session_id: ID of session to close

        Returns:
            True if session was closed
        """
        if session_id not in self._active_sessions:
            return False

        active = self._active_sessions[session_id]

        # Audit: Log connection closed
        self._audit.log_connection_closed(
            host=active.connection.host,
            port=active.connection.port,
            username=active.connection.username,
            reason="Closed by user"
        )

        active.session.disconnect()
        del self._active_sessions[session_id]

        if self.on_session_end:
            self.on_session_end(session_id, "Closed by user")

        return True

    def _handle_session_disconnect(self, session_id: int, reason: str):
        """Handle unexpected session disconnect."""
        if session_id in self._active_sessions:
            active = self._active_sessions[session_id]

            # Audit: Log connection closed
            self._audit.log_connection_closed(
                host=active.connection.host,
                port=active.connection.port,
                username=active.connection.username,
                reason=reason
            )

            del self._active_sessions[session_id]

            if self.on_session_end:
                self.on_session_end(session_id, reason)

    def get_session(self, session_id: int) -> Optional[ActiveSession]:
        """Get an active session by ID."""
        return self._active_sessions.get(session_id)

    def get_active_sessions(self) -> Dict[int, ActiveSession]:
        """Get all active sessions."""
        return self._active_sessions.copy()

    def close_all_sessions(self):
        """Close all active sessions."""
        for session_id in list(self._active_sessions.keys()):
            self.close_session(session_id)

    def quick_connect(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        port: int = 22,
        key_path: Optional[str] = None
    ) -> Optional[int]:
        """
        Quick connect without saving connection.

        Args:
            host: Hostname or IP
            username: SSH username
            password: Optional password
            port: SSH port
            key_path: Optional SSH key path

        Returns:
            Session ID if successful
        """
        connection = Connection(
            name=f"{username}@{host}",
            host=host,
            port=port,
            username=username,
            ssh_key_path=key_path,
            credential_mode='local'
        )

        return self.start_session(connection, password)

    def duplicate_connection(self, connection_id: int) -> Optional[int]:
        """
        Duplicate an existing connection.

        Args:
            connection_id: ID of connection to duplicate

        Returns:
            New connection ID
        """
        connection = self.database.get_connection(connection_id)
        if not connection:
            return None

        connection.id = None
        connection.name = f"{connection.name} (copy)"
        connection.use_count = 0
        connection.last_used = None

        return self.database.add_connection(connection)
