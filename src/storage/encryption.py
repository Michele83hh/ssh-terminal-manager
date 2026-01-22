"""
Encryption module for secure credential storage.
Uses AES-256-GCM with PBKDF2 key derivation or Windows DPAPI.

Security features:
- AES-256-GCM authenticated encryption
- PBKDF2-SHA256 with 600,000 iterations (OWASP 2023 recommendation)
- Constant-time password comparison (timing attack resistant)
- Secure memory clearing for sensitive data
- Master key timeout for enhanced security
"""
import os
import base64
import hashlib
import hmac
import json
import ctypes
import threading
import time
from typing import Optional, Callable
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False


class EncryptionManager:
    """
    Manages encryption/decryption of sensitive data.

    Supports two modes:
    1. Master password mode: AES-256-GCM with key derived via PBKDF2
    2. DPAPI mode: Uses Windows DPAPI via keyring for key storage

    Security features:
    - Master key timeout: Automatically clears key after inactivity
    - Secure memory clearing when key expires
    """

    APP_NAME = "SSHTerminalManager"
    SALT_SIZE = 16
    NONCE_SIZE = 12
    KEY_SIZE = 32  # 256 bits
    ITERATIONS = 600000  # OWASP 2023 recommended for PBKDF2-SHA256
    DEFAULT_TIMEOUT_SECONDS = 15 * 60  # 15 minutes default

    def __init__(self, use_dpapi: bool = True, timeout_seconds: int = None):
        """
        Initialize encryption manager.

        Args:
            use_dpapi: If True, use Windows DPAPI for master key storage.
                      If False, require master password on each session.
            timeout_seconds: Inactivity timeout for master key (0 to disable).
                            Default is 15 minutes.
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography package required for encryption")

        self.use_dpapi = use_dpapi and KEYRING_AVAILABLE
        self._master_key: Optional[bytes] = None
        self._salt: Optional[bytes] = None

        # Timeout configuration
        self._timeout_seconds = timeout_seconds if timeout_seconds is not None else self.DEFAULT_TIMEOUT_SECONDS
        self._last_activity: float = 0
        self._timeout_timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()

        # Callback when master key times out (UI should prompt for password)
        self.on_timeout: Optional[Callable[[], None]] = None

    def is_initialized(self) -> bool:
        """Check if encryption is initialized with a master key."""
        return self._master_key is not None

    def _reset_timeout(self):
        """Reset the inactivity timeout timer."""
        with self._lock:
            self._last_activity = time.time()

            # Cancel existing timer
            if self._timeout_timer:
                self._timeout_timer.cancel()
                self._timeout_timer = None

            # Start new timer if timeout is enabled
            if self._timeout_seconds > 0 and self._master_key is not None:
                self._timeout_timer = threading.Timer(
                    self._timeout_seconds,
                    self._on_timeout
                )
                self._timeout_timer.daemon = True
                self._timeout_timer.start()

    def _on_timeout(self):
        """Handle master key timeout - clear key and notify."""
        with self._lock:
            if self._master_key is not None:
                # Log the timeout
                try:
                    from ..utils.audit_log import AuditLogger, AuditEventType
                    audit = AuditLogger.get_instance()
                    audit.log_master_password_event(AuditEventType.MASTER_PASSWORD_TIMEOUT)
                except ImportError:
                    pass

                # Securely clear the master key
                self._secure_clear_key()

        # Notify callback (outside lock to prevent deadlocks)
        if self.on_timeout:
            self.on_timeout()

    def _secure_clear_key(self):
        """Securely clear the master key from memory."""
        if self._master_key is not None:
            # Overwrite key bytes with zeros
            key_array = bytearray(self._master_key)
            secure_zero_memory(key_array)
            self._master_key = None

    def stop_timeout(self):
        """Stop the timeout timer (call on application exit)."""
        with self._lock:
            if self._timeout_timer:
                self._timeout_timer.cancel()
                self._timeout_timer = None

    def set_timeout(self, seconds: int):
        """Set the inactivity timeout in seconds (0 to disable)."""
        self._timeout_seconds = seconds
        if self._master_key is not None:
            self._reset_timeout()

    def touch(self):
        """Reset the inactivity timeout (call on encryption/decryption activity)."""
        if self._timeout_seconds > 0:
            self._reset_timeout()

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def initialize_with_password(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """
        Initialize encryption with a master password.

        Args:
            password: Master password
            salt: Optional salt (generated if not provided)

        Returns:
            The salt used (save this for later decryption)
        """
        if salt is None:
            salt = os.urandom(self.SALT_SIZE)

        self._salt = salt
        self._master_key = self._derive_key(password, salt)

        if self.use_dpapi:
            # Store master key in Windows Credential Manager
            keyring.set_password(self.APP_NAME, "master_key",
                               base64.b64encode(self._master_key).decode('ascii'))
            keyring.set_password(self.APP_NAME, "salt",
                               base64.b64encode(salt).decode('ascii'))

        # Start inactivity timeout
        self._reset_timeout()

        return salt

    def initialize_from_dpapi(self) -> bool:
        """
        Try to initialize from stored DPAPI credentials.

        Returns:
            True if successful, False if no stored credentials.
        """
        if not self.use_dpapi:
            return False

        try:
            stored_key = keyring.get_password(self.APP_NAME, "master_key")
            stored_salt = keyring.get_password(self.APP_NAME, "salt")

            if stored_key and stored_salt:
                self._master_key = base64.b64decode(stored_key)
                self._salt = base64.b64decode(stored_salt)
                # Start inactivity timeout
                self._reset_timeout()
                return True
        except Exception:
            pass

        return False

    def verify_password(self, password: str) -> bool:
        """Verify if password matches the stored master key.

        Uses constant-time comparison to prevent timing attacks.
        """
        if self._salt is None or self._master_key is None:
            return False

        test_key = self._derive_key(password, self._salt)
        # Use hmac.compare_digest for constant-time comparison (timing attack resistant)
        return hmac.compare_digest(test_key, self._master_key)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a string using AES-256-GCM.

        Args:
            plaintext: String to encrypt

        Returns:
            Base64 encoded string: nonce + ciphertext + tag
        """
        if self._master_key is None:
            raise RuntimeError("Encryption not initialized. Call initialize_with_password first.")

        # Reset inactivity timeout on encryption activity
        self.touch()

        nonce = os.urandom(self.NONCE_SIZE)
        aesgcm = AESGCM(self._master_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

        # Combine nonce + ciphertext (tag is appended by AESGCM)
        encrypted_data = nonce + ciphertext
        return base64.b64encode(encrypted_data).decode('ascii')

    def decrypt(self, encrypted: str) -> str:
        """
        Decrypt an AES-256-GCM encrypted string.

        Args:
            encrypted: Base64 encoded encrypted string

        Returns:
            Decrypted plaintext string
        """
        if self._master_key is None:
            raise RuntimeError("Encryption not initialized. Call initialize_with_password first.")

        # Reset inactivity timeout on decryption activity
        self.touch()

        encrypted_data = base64.b64decode(encrypted)
        nonce = encrypted_data[:self.NONCE_SIZE]
        ciphertext = encrypted_data[self.NONCE_SIZE:]

        aesgcm = AESGCM(self._master_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')

    def encrypt_dict(self, data: dict) -> str:
        """Encrypt a dictionary as JSON."""
        return self.encrypt(json.dumps(data))

    def decrypt_dict(self, encrypted: str) -> dict:
        """Decrypt a dictionary from encrypted JSON."""
        return json.loads(self.decrypt(encrypted))

    def clear_dpapi(self):
        """Remove stored credentials from Windows Credential Manager."""
        if self.use_dpapi:
            try:
                keyring.delete_password(self.APP_NAME, "master_key")
                keyring.delete_password(self.APP_NAME, "salt")
            except Exception:
                pass

    def get_salt(self) -> Optional[bytes]:
        """Get current salt (needed for password re-verification)."""
        return self._salt

    def save_salt_to_file(self, path: Path):
        """Save salt to a file for persistence."""
        if self._salt:
            path.write_bytes(self._salt)

    def load_salt_from_file(self, path: Path) -> bool:
        """Load salt from a file."""
        if path.exists():
            self._salt = path.read_bytes()
            return True
        return False


def secure_zero_memory(buffer: bytearray) -> None:
    """
    Securely zero out memory buffer to prevent sensitive data recovery.

    Uses ctypes to ensure the memory is actually zeroed and not optimized away.
    """
    if buffer is None:
        return

    size = len(buffer)
    if size == 0:
        return

    # Get the address of the buffer
    ptr = (ctypes.c_char * size).from_buffer(buffer)
    # Zero the memory
    ctypes.memset(ctypes.addressof(ptr), 0, size)


class SecureString:
    """
    A string wrapper that securely clears memory when done.

    Usage:
        with SecureString(password) as secure_pw:
            # use secure_pw.value
        # memory is securely cleared after the with block
    """

    def __init__(self, value: str):
        self._buffer = bytearray(value.encode('utf-8'))

    @property
    def value(self) -> str:
        return self._buffer.decode('utf-8')

    def clear(self):
        """Securely clear the string from memory."""
        secure_zero_memory(self._buffer)
        self._buffer = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()
        return False

    def __del__(self):
        self.clear()


class PasswordHasher:
    """
    Password hashing for verification without storing plaintext.

    Uses PBKDF2-SHA256 with 600,000 iterations (OWASP 2023 recommendation).
    """

    ITERATIONS = 600000  # OWASP 2023 recommendation

    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
        """
        Hash a password with salt using PBKDF2-SHA256.

        Returns:
            Tuple of (hash, salt) as base64 strings
        """
        if salt is None:
            salt = os.urandom(16)

        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            PasswordHasher.ITERATIONS
        )
        return (
            base64.b64encode(key).decode('ascii'),
            base64.b64encode(salt).decode('ascii')
        )

    @staticmethod
    def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
        """
        Verify a password against stored hash.

        Uses constant-time comparison to prevent timing attacks.
        """
        salt = base64.b64decode(stored_salt)
        computed_hash, _ = PasswordHasher.hash_password(password, salt)
        # Use hmac.compare_digest for constant-time comparison
        return hmac.compare_digest(
            computed_hash.encode('ascii'),
            stored_hash.encode('ascii')
        )
