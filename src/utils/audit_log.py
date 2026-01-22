"""
Audit logging for security-relevant events.

Logs connection attempts, authentication events, and security-related actions
to a secure, append-only log file.

Log format: ISO timestamp | Event Type | Details (JSON)
"""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from enum import Enum

from .file_security import secure_file_permissions, secure_directory_permissions


class AuditEventType(Enum):
    """Types of auditable security events."""
    # Connection events
    CONNECTION_ATTEMPT = "CONNECTION_ATTEMPT"
    CONNECTION_SUCCESS = "CONNECTION_SUCCESS"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    CONNECTION_CLOSED = "CONNECTION_CLOSED"

    # Authentication events
    AUTH_PASSWORD = "AUTH_PASSWORD"
    AUTH_KEY = "AUTH_KEY"
    AUTH_FAILED = "AUTH_FAILED"

    # Host key events
    HOST_KEY_NEW = "HOST_KEY_NEW"
    HOST_KEY_ACCEPTED = "HOST_KEY_ACCEPTED"
    HOST_KEY_REJECTED = "HOST_KEY_REJECTED"
    HOST_KEY_CHANGED = "HOST_KEY_CHANGED"

    # Master password events
    MASTER_PASSWORD_SET = "MASTER_PASSWORD_SET"
    MASTER_PASSWORD_VERIFIED = "MASTER_PASSWORD_VERIFIED"
    MASTER_PASSWORD_FAILED = "MASTER_PASSWORD_FAILED"
    MASTER_PASSWORD_TIMEOUT = "MASTER_PASSWORD_TIMEOUT"

    # Session events
    SESSION_START = "SESSION_START"
    SESSION_END = "SESSION_END"
    SESSION_TIMEOUT = "SESSION_TIMEOUT"

    # Configuration events
    CONNECTION_CREATED = "CONNECTION_CREATED"
    CONNECTION_MODIFIED = "CONNECTION_MODIFIED"
    CONNECTION_DELETED = "CONNECTION_DELETED"

    # Import/Export
    CONNECTIONS_EXPORTED = "CONNECTIONS_EXPORTED"
    CONNECTIONS_IMPORTED = "CONNECTIONS_IMPORTED"


class AuditLogger:
    """
    Secure audit logger for security events.

    Features:
    - Append-only logging
    - Secure file permissions
    - Structured JSON format
    - No sensitive data (passwords, keys) logged
    """

    _instance: Optional['AuditLogger'] = None

    def __init__(self, log_path: Optional[Path] = None):
        if log_path is None:
            log_path = Path(__file__).parent.parent.parent / "data" / "audit.log"
        self.log_path = log_path
        self._ensure_log_file()

    @classmethod
    def get_instance(cls) -> 'AuditLogger':
        """Get singleton instance of audit logger."""
        if cls._instance is None:
            cls._instance = AuditLogger()
        return cls._instance

    def _ensure_log_file(self):
        """Ensure log file and directory exist with secure permissions."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.log_path.exists():
            self.log_path.touch()

        # Set secure permissions
        secure_directory_permissions(self.log_path.parent)
        secure_file_permissions(self.log_path)

    def log(
        self,
        event_type: AuditEventType,
        details: Optional[Dict[str, Any]] = None,
        username: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        success: Optional[bool] = None,
        error: Optional[str] = None
    ):
        """
        Log a security event.

        Args:
            event_type: Type of event
            details: Additional details (must not contain sensitive data!)
            username: SSH username (if applicable)
            host: Target host (if applicable)
            port: Target port (if applicable)
            success: Whether operation succeeded
            error: Error message (if applicable)
        """
        timestamp = datetime.now().isoformat()

        entry = {
            'timestamp': timestamp,
            'event': event_type.value,
        }

        if username:
            entry['username'] = username
        if host:
            entry['host'] = host
        if port:
            entry['port'] = port
        if success is not None:
            entry['success'] = success
        if error:
            entry['error'] = error
        if details:
            # Sanitize details - remove any potential sensitive data
            safe_details = self._sanitize_details(details)
            if safe_details:
                entry['details'] = safe_details

        log_line = json.dumps(entry, separators=(',', ':'))

        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(log_line + '\n')
        except Exception:
            pass  # Fail silently - logging should never break the app

    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove sensitive data from details dict.

        Strips: passwords, keys, tokens, secrets, credentials
        """
        sensitive_keys = {
            'password', 'passwd', 'pwd', 'secret', 'token',
            'key', 'credential', 'auth', 'private', 'passphrase'
        }

        sanitized = {}
        for key, value in details.items():
            key_lower = key.lower()
            # Skip if key contains sensitive words
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                continue
            # Recursively sanitize nested dicts
            if isinstance(value, dict):
                value = self._sanitize_details(value)
            sanitized[key] = value

        return sanitized

    # Convenience methods for common events

    def log_connection_attempt(self, host: str, port: int, username: str):
        """Log an SSH connection attempt."""
        self.log(
            AuditEventType.CONNECTION_ATTEMPT,
            host=host,
            port=port,
            username=username
        )

    def log_connection_success(self, host: str, port: int, username: str):
        """Log a successful SSH connection."""
        self.log(
            AuditEventType.CONNECTION_SUCCESS,
            host=host,
            port=port,
            username=username,
            success=True
        )

    def log_connection_failed(self, host: str, port: int, username: str, error: str):
        """Log a failed SSH connection."""
        self.log(
            AuditEventType.CONNECTION_FAILED,
            host=host,
            port=port,
            username=username,
            success=False,
            error=error
        )

    def log_connection_closed(self, host: str, port: int, username: str, reason: str = None):
        """Log an SSH connection closure."""
        self.log(
            AuditEventType.CONNECTION_CLOSED,
            host=host,
            port=port,
            username=username,
            details={'reason': reason} if reason else None
        )

    def log_host_key_event(
        self,
        event_type: AuditEventType,
        host: str,
        port: int,
        key_type: str,
        fingerprint: str
    ):
        """Log a host key verification event."""
        self.log(
            event_type,
            host=host,
            port=port,
            details={
                'key_type': key_type,
                'fingerprint': fingerprint
            }
        )

    def log_master_password_event(self, event_type: AuditEventType):
        """Log a master password event."""
        self.log(event_type)

    def log_session_event(
        self,
        event_type: AuditEventType,
        session_id: int,
        host: str = None,
        username: str = None,
        reason: str = None
    ):
        """Log a session lifecycle event."""
        details = {'session_id': session_id}
        if reason:
            details['reason'] = reason
        self.log(
            event_type,
            host=host,
            username=username,
            details=details
        )

    def get_recent_events(self, count: int = 100) -> list:
        """
        Get most recent audit events.

        Args:
            count: Number of events to retrieve

        Returns:
            List of event dicts, newest first
        """
        events = []
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Parse last N lines
            for line in reversed(lines[-count:]):
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass

        return events


# Global convenience function
def audit_log(
    event_type: AuditEventType,
    **kwargs
):
    """Log an audit event using the global logger."""
    AuditLogger.get_instance().log(event_type, **kwargs)
