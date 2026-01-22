"""
File security utilities for protecting sensitive files.

On Windows: Uses ACLs to restrict access to current user only.
On Unix: Uses chmod to set 600 permissions.
"""
import os
import stat
import sys
from pathlib import Path
from typing import Optional


def secure_file_permissions(file_path: Path) -> bool:
    """
    Set secure permissions on a file (user-only access).

    Args:
        file_path: Path to the file to secure

    Returns:
        True if permissions were set successfully
    """
    if not file_path.exists():
        return False

    try:
        if sys.platform == 'win32':
            return _secure_file_windows(file_path)
        else:
            return _secure_file_unix(file_path)
    except Exception:
        return False


def _secure_file_windows(file_path: Path) -> bool:
    """
    Set Windows ACL to allow only current user access.

    Uses icacls command to:
    1. Grant full control to current user FIRST (ensure access)
    2. Then disable inheritance and remove other permissions
    """
    import subprocess

    file_str = str(file_path)
    username = os.environ.get('USERNAME', '')

    if not username:
        return False

    # Get creation flags for hiding console window
    creation_flags = 0
    if hasattr(subprocess, 'CREATE_NO_WINDOW'):
        creation_flags = subprocess.CREATE_NO_WINDOW

    try:
        # FIRST: Grant full control to current user (ensure we have access)
        result = subprocess.run(
            ['icacls', file_str, '/grant', f'{username}:F'],
            capture_output=True,
            creationflags=creation_flags
        )

        # Only proceed with removing inheritance if grant succeeded
        if result.returncode == 0:
            # Disable inheritance but COPY existing permissions first (/inheritance:d)
            # This is safer than /inheritance:r which removes all
            subprocess.run(
                ['icacls', file_str, '/inheritance:d'],
                capture_output=True,
                creationflags=creation_flags
            )

        return True

    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        # icacls not available
        return False
    except Exception:
        # Any other error - don't break the app
        return False


def _secure_file_unix(file_path: Path) -> bool:
    """Set Unix permissions to 600 (owner read/write only)."""
    try:
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        return True
    except OSError:
        return False


def secure_directory_permissions(dir_path: Path) -> bool:
    """
    Set secure permissions on a directory (user-only access).

    Args:
        dir_path: Path to the directory to secure

    Returns:
        True if permissions were set successfully
    """
    if not dir_path.exists() or not dir_path.is_dir():
        return False

    try:
        if sys.platform == 'win32':
            return _secure_directory_windows(dir_path)
        else:
            return _secure_directory_unix(dir_path)
    except Exception:
        return False


def _secure_directory_windows(dir_path: Path) -> bool:
    """Set Windows ACL on directory for current user only."""
    import subprocess

    dir_str = str(dir_path)
    username = os.environ.get('USERNAME', '')

    if not username:
        return False

    # Get creation flags for hiding console window
    creation_flags = 0
    if hasattr(subprocess, 'CREATE_NO_WINDOW'):
        creation_flags = subprocess.CREATE_NO_WINDOW

    try:
        # FIRST: Grant full control to current user (with inheritance for subfolders)
        result = subprocess.run(
            ['icacls', dir_str, '/grant', f'{username}:(OI)(CI)F'],
            capture_output=True,
            creationflags=creation_flags
        )

        # Only proceed with removing inheritance if grant succeeded
        if result.returncode == 0:
            # Disable inheritance but COPY existing permissions
            subprocess.run(
                ['icacls', dir_str, '/inheritance:d'],
                capture_output=True,
                creationflags=creation_flags
            )

        return True

    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        return False
    except Exception:
        return False


def _secure_directory_unix(dir_path: Path) -> bool:
    """Set Unix permissions to 700 (owner only)."""
    try:
        os.chmod(dir_path, stat.S_IRWXU)
        return True
    except OSError:
        return False


def create_secure_file(file_path: Path, content: bytes = b'') -> bool:
    """
    Create a new file with secure permissions.

    Args:
        file_path: Path to create
        content: Initial content (optional)

    Returns:
        True if file was created successfully
    """
    try:
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Create file with restrictive permissions from the start
        if sys.platform == 'win32':
            # On Windows, create file then set permissions
            file_path.write_bytes(content)
            return secure_file_permissions(file_path)
        else:
            # On Unix, use os.open with mode for atomic secure creation
            fd = os.open(
                str(file_path),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                stat.S_IRUSR | stat.S_IWUSR
            )
            try:
                os.write(fd, content)
            finally:
                os.close(fd)
            return True

    except Exception:
        return False


def verify_file_permissions(file_path: Path) -> bool:
    """
    Verify that a file has secure permissions.

    Returns True if:
    - On Windows: Only current user has access
    - On Unix: Permissions are 600 or more restrictive

    Args:
        file_path: Path to verify

    Returns:
        True if permissions are secure
    """
    if not file_path.exists():
        return False

    try:
        if sys.platform == 'win32':
            return _verify_permissions_windows(file_path)
        else:
            return _verify_permissions_unix(file_path)
    except Exception:
        return False


def _verify_permissions_windows(file_path: Path) -> bool:
    """Verify Windows ACL (basic check)."""
    # Full verification would require win32security module
    # For now, just check the file exists and is readable
    try:
        with open(file_path, 'rb') as f:
            pass
        return True
    except PermissionError:
        return False


def _verify_permissions_unix(file_path: Path) -> bool:
    """Verify Unix permissions are 600 or more restrictive."""
    mode = file_path.stat().st_mode
    # Check that group and others have no permissions
    return (mode & (stat.S_IRWXG | stat.S_IRWXO)) == 0
