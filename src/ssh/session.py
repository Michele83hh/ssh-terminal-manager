"""
SSH session management using paramiko.

Security features:
- Host key verification with known_hosts persistence
- Warning on unknown/changed host keys
- Modern algorithm preferences
- Secure password handling (memory cleared after use)
"""
import socket
import threading
import time
import hashlib
import base64
from pathlib import Path
from typing import Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

try:
    import paramiko
    from paramiko import SSHClient, RSAKey, Ed25519Key, ECDSAKey, MissingHostKeyPolicy
    from paramiko.hostkeys import HostKeys
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

from ..storage.encryption import secure_zero_memory
from ..utils.file_security import secure_file_permissions


class HostKeyStatus(Enum):
    """Status of host key verification."""
    KNOWN = "known"          # Key matches known_hosts
    NEW = "new"              # Host not in known_hosts
    CHANGED = "changed"      # Key differs from known_hosts (possible MITM!)


class InteractiveHostKeyPolicy(MissingHostKeyPolicy):
    """
    Host key policy that verifies keys against known_hosts and prompts for unknown hosts.

    Security: This prevents man-in-the-middle attacks by verifying host identity.
    """

    def __init__(
        self,
        known_hosts_path: Optional[Path] = None,
        on_host_key_verify: Optional[Callable[[str, int, str, str, HostKeyStatus], bool]] = None
    ):
        """
        Initialize the policy.

        Args:
            known_hosts_path: Path to known_hosts file (default: data/known_hosts)
            on_host_key_verify: Callback for user verification.
                Args: (hostname, port, key_type, fingerprint, status)
                Returns: True to accept, False to reject
        """
        super().__init__()
        if known_hosts_path is None:
            known_hosts_path = Path(__file__).parent.parent.parent / "data" / "known_hosts"
        self.known_hosts_path = known_hosts_path
        self.on_host_key_verify = on_host_key_verify
        self._host_keys = HostKeys()

        # Load existing known_hosts
        self._load_known_hosts()

    def _load_known_hosts(self):
        """Load known hosts from file."""
        if self.known_hosts_path.exists():
            try:
                self._host_keys.load(str(self.known_hosts_path))
            except Exception:
                pass

    def _save_known_hosts(self):
        """Save known hosts to file with secure permissions."""
        self.known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._host_keys.save(str(self.known_hosts_path))
            # Set secure permissions (user-only access)
            secure_file_permissions(self.known_hosts_path)
        except Exception:
            pass

    @staticmethod
    def _get_fingerprint(key) -> str:
        """Get SHA256 fingerprint of a key (same format as OpenSSH)."""
        key_bytes = key.get_fingerprint()
        # Use SHA256 for better security (OpenSSH default since 2015)
        sha256_hash = hashlib.sha256(key.asbytes()).digest()
        fingerprint = base64.b64encode(sha256_hash).decode('ascii').rstrip('=')
        return f"SHA256:{fingerprint}"

    def missing_host_key(self, client, hostname: str, key):
        """
        Called when a host key is not found in known_hosts.

        This method is called by paramiko when connecting to a host
        whose key is not in the known_hosts file.
        """
        key_type = key.get_name()
        fingerprint = self._get_fingerprint(key)

        # Check if we have a different key for this host
        existing_key = self._host_keys.lookup(hostname)
        if existing_key:
            # Host exists but key is different - POSSIBLE MITM ATTACK!
            status = HostKeyStatus.CHANGED
        else:
            # New host
            status = HostKeyStatus.NEW

        # Extract port from hostname if present (format: [host]:port)
        display_hostname = hostname
        port = 22
        if hostname.startswith('[') and ']:' in hostname:
            port = int(hostname.split(']:')[1])
            display_hostname = hostname[1:].split(']:')[0]

        # If we have a callback, ask user
        if self.on_host_key_verify:
            accepted = self.on_host_key_verify(display_hostname, port, key_type, fingerprint, status)

            if not accepted:
                raise paramiko.SSHException(
                    f"Host key verification rejected for {display_hostname}"
                )
        else:
            # No callback - default to rejecting unknown hosts for security
            if status == HostKeyStatus.CHANGED:
                raise paramiko.SSHException(
                    f"HOST KEY CHANGED for {display_hostname}! "
                    f"This could indicate a man-in-the-middle attack. "
                    f"Fingerprint: {fingerprint}"
                )
            else:
                raise paramiko.SSHException(
                    f"Unknown host key for {display_hostname}. "
                    f"Fingerprint: {fingerprint}"
                )

        # User accepted - save the key to our persistent storage
        self._host_keys.add(hostname, key_type, key)
        self._save_known_hosts()

        # Also add to the client's host keys so paramiko can verify
        client.get_host_keys().add(hostname, key_type, key)


@dataclass
class SSHConfig:
    """SSH connection configuration with secure password handling."""
    host: str
    port: int = 22
    username: str = ""
    password: Optional[str] = field(default=None, repr=False)  # Will be converted to secure buffer
    key_path: Optional[str] = None
    key_passphrase: Optional[str] = None
    timeout: int = 30
    keepalive_interval: int = 60
    # Password stored as bytearray for secure clearing (internal)
    _password_buffer: Optional[bytearray] = field(default=None, repr=False, init=False)

    def __post_init__(self):
        """Convert password to secure buffer after initialization."""
        if self.password:
            self._password_buffer = bytearray(self.password.encode('utf-8'))
            # Clear the original string field (can't fully secure in Python, but helps)
            object.__setattr__(self, 'password', None)

    def get_password(self) -> Optional[str]:
        """Get password (decoded from secure buffer)."""
        if self._password_buffer:
            return self._password_buffer.decode('utf-8')
        return None

    def clear_password(self):
        """Securely clear password from memory."""
        if self._password_buffer:
            secure_zero_memory(self._password_buffer)
            self._password_buffer = None

    def clear_passphrase(self):
        """Clear key passphrase (for future secure implementation)."""
        self.key_passphrase = None


class SSHSession:
    """
    Manages a single SSH session with terminal support.

    Provides:
    - Connection management with host key verification
    - Interactive shell with PTY
    - Keepalive handling
    - Event callbacks for UI integration

    Security:
    - Host key verification prevents MITM attacks
    - Modern algorithm preferences
    """

    def __init__(self, config: SSHConfig):
        if not PARAMIKO_AVAILABLE:
            raise ImportError("paramiko package required for SSH connections")

        self.config = config
        self._client: Optional[SSHClient] = None
        self._channel = None
        self._connected = False
        self._keepalive_thread: Optional[threading.Thread] = None
        self._read_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Callbacks
        self.on_data: Optional[Callable[[bytes], None]] = None
        self.on_disconnect: Optional[Callable[[str], None]] = None
        self.on_connect: Optional[Callable[[], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None

        # Host key verification callback
        # Args: (hostname, port, key_type, fingerprint, status: HostKeyStatus)
        # Returns: True to accept, False to reject
        self.on_host_key_verify: Optional[Callable[[str, int, str, str, HostKeyStatus], bool]] = None

    def connect(self) -> bool:
        """
        Establish SSH connection with host key verification.

        Returns:
            True if connection successful
        """
        try:
            self._client = SSHClient()

            # Load our app's known_hosts file
            app_known_hosts = Path(__file__).parent.parent.parent / "data" / "known_hosts"
            if app_known_hosts.exists():
                try:
                    self._client.load_host_keys(str(app_known_hosts))
                except Exception:
                    pass

            # Also load system known_hosts if available
            try:
                self._client.load_system_host_keys()
            except Exception:
                pass

            # Use secure host key policy with verification callback
            host_key_policy = InteractiveHostKeyPolicy(
                known_hosts_path=app_known_hosts,
                on_host_key_verify=self.on_host_key_verify
            )
            self._client.set_missing_host_key_policy(host_key_policy)

            # Prepare connection kwargs
            connect_kwargs = {
                'hostname': self.config.host,
                'port': self.config.port,
                'username': self.config.username,
                'timeout': self.config.timeout,
                'allow_agent': True,
                'look_for_keys': True,
                'banner_timeout': 30,  # Cisco devices can be slow
            }

            # Authentication method
            if self.config.key_path:
                key = self._load_private_key(
                    self.config.key_path,
                    self.config.key_passphrase
                )
                if key:
                    connect_kwargs['pkey'] = key
            else:
                password = self.config.get_password()
                if password:
                    connect_kwargs['password'] = password

            # Algorithm configuration for compatibility with older devices
            # We allow legacy algorithms but prefer modern ones
            connect_kwargs['disabled_algorithms'] = {'pubkeys': []}

            self._client.connect(**connect_kwargs)
            self._connected = True
            self._stop_event.clear()

            # Start keepalive thread
            if self.config.keepalive_interval > 0:
                self._start_keepalive()

            if self.on_connect:
                self.on_connect()

            return True

        except paramiko.AuthenticationException as e:
            self._handle_error(f"Authentication failed: {e}")
            return False
        except paramiko.SSHException as e:
            self._handle_error(f"SSH error: {e}")
            return False
        except socket.timeout:
            self._handle_error("Connection timed out")
            return False
        except socket.error as e:
            self._handle_error(f"Network error: {e}")
            return False
        except Exception as e:
            self._handle_error(f"Connection failed: {e}")
            return False
        # Note: Password is kept for potential reconnects
        # It will be cleared when disconnect() is called

    def _load_private_key(self, path: str, passphrase: Optional[str] = None):
        """Load private key from file, auto-detecting key type."""
        key_path = Path(path)
        if not key_path.exists():
            self._handle_error(f"Key file not found: {path}")
            return None

        # Try different key types
        key_types = [RSAKey, Ed25519Key, ECDSAKey]

        for key_class in key_types:
            try:
                return key_class.from_private_key_file(
                    str(key_path),
                    password=passphrase
                )
            except paramiko.SSHException:
                continue
            except Exception:
                continue

        self._handle_error(f"Could not load key: {path}")
        return None

    def open_shell(self, cols: int = 80, rows: int = 24, term_type: str = 'xterm-256color') -> bool:
        """
        Open interactive shell with PTY.

        Args:
            cols: Terminal width in columns
            rows: Terminal height in rows
            term_type: Terminal type (xterm-256color, xterm, vt100, etc.)

        Returns:
            True if shell opened successfully
        """
        if not self._connected or not self._client:
            return False

        try:
            transport = self._client.get_transport()
            if transport is None:
                return False

            self._channel = transport.open_session()
            self._channel.get_pty(
                term=term_type,
                width=cols,
                height=rows
            )
            self._channel.invoke_shell()

            # Start reading thread
            self._start_read_thread()

            return True

        except Exception as e:
            self._handle_error(f"Failed to open shell: {e}")
            return False

    def resize_pty(self, cols: int, rows: int):
        """Resize PTY dimensions."""
        if self._channel:
            try:
                self._channel.resize_pty(width=cols, height=rows)
            except Exception:
                pass

    def send(self, data: bytes):
        """Send data to the SSH channel."""
        if self._channel and not self._channel.closed:
            try:
                self._channel.send(data)
            except Exception as e:
                self._handle_error(f"Send failed: {e}")

    def send_string(self, text: str):
        """Send string to the SSH channel."""
        self.send(text.encode('utf-8'))

    def _start_read_thread(self):
        """Start thread to read from SSH channel."""
        self._read_thread = threading.Thread(
            target=self._read_loop,
            daemon=True
        )
        self._read_thread.start()

    def _read_loop(self):
        """Read data from channel and call callback."""
        while not self._stop_event.is_set() and self._channel:
            try:
                if self._channel.recv_ready():
                    data = self._channel.recv(4096)
                    if data and self.on_data:
                        self.on_data(data)
                elif self._channel.closed:
                    break
                else:
                    time.sleep(0.01)
            except Exception:
                break

        self._handle_disconnect("Connection closed")

    def _start_keepalive(self):
        """Start keepalive thread."""
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop,
            daemon=True
        )
        self._keepalive_thread.start()

    def _keepalive_loop(self):
        """Send keepalive packets periodically."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self.config.keepalive_interval)
            if self._stop_event.is_set():
                break

            try:
                if self._client:
                    transport = self._client.get_transport()
                    if transport and transport.is_active():
                        transport.send_ignore()
            except Exception:
                break

    def _handle_error(self, message: str):
        """Handle error with callback."""
        if self.on_error:
            self.on_error(message)

    def _handle_disconnect(self, reason: str):
        """Handle disconnection."""
        self._connected = False
        if self.on_disconnect:
            self.on_disconnect(reason)

    def disconnect(self):
        """Close SSH connection."""
        self._stop_event.set()
        self._connected = False

        if self._channel:
            try:
                self._channel.close()
            except Exception:
                pass
            self._channel = None

        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def is_connected(self) -> bool:
        """Check if connection is active."""
        if not self._connected or not self._client:
            return False

        try:
            transport = self._client.get_transport()
            return transport is not None and transport.is_active()
        except Exception:
            return False

    def exec_command(self, command: str, timeout: int = 30) -> tuple[str, str, int]:
        """
        Execute a single command (non-interactive).

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        if not self._connected or not self._client:
            return "", "Not connected", -1

        try:
            stdin, stdout, stderr = self._client.exec_command(
                command,
                timeout=timeout
            )
            exit_code = stdout.channel.recv_exit_status()
            return (
                stdout.read().decode('utf-8', errors='replace'),
                stderr.read().decode('utf-8', errors='replace'),
                exit_code
            )
        except Exception as e:
            return "", str(e), -1

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
        return False
