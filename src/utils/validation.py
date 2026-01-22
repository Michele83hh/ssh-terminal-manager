"""
Input validation utilities for security.

Provides validation and sanitization functions to prevent:
- Path traversal attacks
- Command injection
- Invalid hostnames/IPs
- Malformed input
"""
import re
import ipaddress
from typing import Optional, Tuple


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


def validate_hostname(hostname: str) -> str:
    """
    Validate and sanitize a hostname or IP address.

    Args:
        hostname: The hostname or IP to validate

    Returns:
        Sanitized hostname

    Raises:
        ValidationError: If hostname is invalid
    """
    if not hostname or not hostname.strip():
        raise ValidationError("Hostname cannot be empty")

    hostname = hostname.strip()

    # Check for dangerous characters
    if any(c in hostname for c in [';', '|', '&', '$', '`', '\n', '\r', '\x00']):
        raise ValidationError("Hostname contains invalid characters")

    # Try to parse as IP address first
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    # Validate as hostname
    # RFC 1123: hostname labels can contain letters, digits, and hyphens
    # Must not start or end with hyphen
    hostname_regex = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$'
    fqdn_regex = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*$'

    if not re.match(fqdn_regex, hostname):
        raise ValidationError(
            f"Invalid hostname: {hostname}. "
            "Must be a valid hostname or IP address."
        )

    # Maximum length check (253 characters for FQDN)
    if len(hostname) > 253:
        raise ValidationError("Hostname too long (max 253 characters)")

    return hostname


def validate_port(port: int) -> int:
    """
    Validate a port number.

    Args:
        port: The port number to validate

    Returns:
        Validated port number

    Raises:
        ValidationError: If port is invalid
    """
    if not isinstance(port, int):
        try:
            port = int(port)
        except (ValueError, TypeError):
            raise ValidationError("Port must be a number")

    if port < 1 or port > 65535:
        raise ValidationError("Port must be between 1 and 65535")

    return port


def validate_username(username: str) -> str:
    """
    Validate and sanitize a username.

    Args:
        username: The username to validate

    Returns:
        Sanitized username

    Raises:
        ValidationError: If username is invalid
    """
    if not username or not username.strip():
        raise ValidationError("Username cannot be empty")

    username = username.strip()

    # Maximum length
    if len(username) > 256:
        raise ValidationError("Username too long (max 256 characters)")

    # Check for dangerous characters (null bytes, etc.)
    if '\x00' in username:
        raise ValidationError("Username contains invalid characters")

    return username


def validate_connection_name(name: str) -> str:
    """
    Validate and sanitize a connection name.

    Args:
        name: The connection name to validate

    Returns:
        Sanitized name

    Raises:
        ValidationError: If name is invalid
    """
    if not name or not name.strip():
        raise ValidationError("Connection name cannot be empty")

    name = name.strip()

    # Maximum length
    if len(name) > 255:
        raise ValidationError("Connection name too long (max 255 characters)")

    # Check for dangerous characters
    if any(c in name for c in ['\x00', '\n', '\r']):
        raise ValidationError("Connection name contains invalid characters")

    return name


def validate_group_name(name: str) -> str:
    """
    Validate and sanitize a group name.

    Args:
        name: The group name to validate

    Returns:
        Sanitized name

    Raises:
        ValidationError: If name is invalid
    """
    if not name or not name.strip():
        raise ValidationError("Group name cannot be empty")

    name = name.strip()

    # Maximum length
    if len(name) > 100:
        raise ValidationError("Group name too long (max 100 characters)")

    # Check for dangerous characters
    if any(c in name for c in ['\x00', '\n', '\r']):
        raise ValidationError("Group name contains invalid characters")

    return name


def validate_file_path(path: str, must_exist: bool = False) -> str:
    """
    Validate a file path for security.

    Prevents path traversal attacks.

    Args:
        path: The file path to validate
        must_exist: If True, verify the file exists

    Returns:
        Validated path

    Raises:
        ValidationError: If path is invalid or dangerous
    """
    if not path or not path.strip():
        raise ValidationError("File path cannot be empty")

    path = path.strip()

    # Check for null bytes (could bypass security checks)
    if '\x00' in path:
        raise ValidationError("File path contains invalid characters")

    # Check for path traversal patterns
    # Note: This is a basic check, additional checks may be needed
    dangerous_patterns = ['../', '..\\', '/../', '\\..\\']
    for pattern in dangerous_patterns:
        if pattern in path:
            raise ValidationError("Path traversal detected in file path")

    # Normalize path
    from pathlib import Path as PathLib
    try:
        normalized = PathLib(path).resolve()
    except Exception as e:
        raise ValidationError(f"Invalid file path: {e}")

    if must_exist and not normalized.exists():
        raise ValidationError(f"File does not exist: {path}")

    return str(normalized)


def sanitize_for_display(text: str, max_length: int = 1000) -> str:
    """
    Sanitize text for safe display.

    Removes control characters and truncates if too long.

    Args:
        text: Text to sanitize
        max_length: Maximum length

    Returns:
        Sanitized text
    """
    if not text:
        return ""

    # Remove control characters except newline and tab
    sanitized = ''.join(
        c for c in text
        if c in '\n\t' or (ord(c) >= 32 and ord(c) != 127)
    )

    # Truncate if too long
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."

    return sanitized


def validate_timeout(timeout: int, min_val: int = 1, max_val: int = 3600) -> int:
    """
    Validate a timeout value.

    Args:
        timeout: Timeout in seconds
        min_val: Minimum allowed value
        max_val: Maximum allowed value

    Returns:
        Validated timeout

    Raises:
        ValidationError: If timeout is invalid
    """
    if not isinstance(timeout, int):
        try:
            timeout = int(timeout)
        except (ValueError, TypeError):
            raise ValidationError("Timeout must be a number")

    if timeout < min_val or timeout > max_val:
        raise ValidationError(f"Timeout must be between {min_val} and {max_val}")

    return timeout
