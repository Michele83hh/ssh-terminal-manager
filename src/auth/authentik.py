"""
Authentik OAuth2/OIDC authentication with PKCE.
"""
import secrets
import hashlib
import base64
import webbrowser
import threading
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, parse_qs, urlparse
from typing import Optional, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False


@dataclass
class AuthentikConfig:
    """Authentik OAuth2 configuration."""
    base_url: str  # e.g., "https://auth.example.com"
    client_id: str
    redirect_port: int = 8400
    scopes: str = "openid profile email"


@dataclass
class TokenInfo:
    """OAuth2 token information."""
    access_token: str
    refresh_token: Optional[str]
    expires_at: datetime
    id_token: Optional[str] = None
    token_type: str = "Bearer"

    def is_expired(self) -> bool:
        """Check if access token is expired."""
        return datetime.now() >= self.expires_at

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'expires_at': self.expires_at.isoformat(),
            'id_token': self.id_token,
            'token_type': self.token_type
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'TokenInfo':
        """Create from dictionary."""
        return cls(
            access_token=data['access_token'],
            refresh_token=data.get('refresh_token'),
            expires_at=datetime.fromisoformat(data['expires_at']),
            id_token=data.get('id_token'),
            token_type=data.get('token_type', 'Bearer')
        )


@dataclass
class UserInfo:
    """User information from OIDC."""
    sub: str  # Subject (unique user ID)
    email: Optional[str] = None
    name: Optional[str] = None
    preferred_username: Optional[str] = None
    groups: Optional[list] = None


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for OAuth callback."""

    def log_message(self, format, *args):
        """Suppress logging."""
        pass

    def do_GET(self):
        """Handle GET request (OAuth callback)."""
        parsed = urlparse(self.path)
        if parsed.path == '/callback':
            query = parse_qs(parsed.query)

            if 'code' in query:
                self.server.auth_code = query['code'][0]
                self.server.auth_state = query.get('state', [None])[0]
                self._send_success()
            elif 'error' in query:
                self.server.auth_error = query['error'][0]
                self._send_error(query.get('error_description', ['Unknown error'])[0])
            else:
                self._send_error("Invalid callback")
        else:
            self.send_error(404)

    def _send_success(self):
        """Send success response."""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = '''<!DOCTYPE html>
<html>
<head><title>Login Successful</title></head>
<body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
    <h1>Login Successful!</h1>
    <p>You can close this window and return to SSH Terminal Manager.</p>
    <script>setTimeout(function(){ window.close(); }, 2000);</script>
</body>
</html>'''
        self.wfile.write(html.encode())

    def _send_error(self, message: str):
        """Send error response."""
        self.send_response(400)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = f'''<!DOCTYPE html>
<html>
<head><title>Login Failed</title></head>
<body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
    <h1>Login Failed</h1>
    <p>{message}</p>
</body>
</html>'''
        self.wfile.write(html.encode())


class AuthentikAuth:
    """
    Authentik OAuth2/OIDC authentication handler.

    Implements:
    - Authorization Code Flow with PKCE
    - Token refresh
    - Token storage via keyring
    - User info retrieval
    """

    APP_NAME = "SSHTerminalManager"

    def __init__(self, config: AuthentikConfig):
        if not HTTPX_AVAILABLE:
            raise ImportError("httpx package required for OAuth2")

        self.config = config
        self._token: Optional[TokenInfo] = None
        self._user_info: Optional[UserInfo] = None

        # OIDC endpoints (will be discovered)
        self._authorization_endpoint: Optional[str] = None
        self._token_endpoint: Optional[str] = None
        self._userinfo_endpoint: Optional[str] = None
        self._end_session_endpoint: Optional[str] = None

        # Callbacks
        self.on_login: Optional[Callable[[UserInfo], None]] = None
        self.on_logout: Optional[Callable[[], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None

    def _discover_endpoints(self) -> bool:
        """Discover OIDC endpoints from well-known configuration."""
        try:
            url = f"{self.config.base_url}/.well-known/openid-configuration"
            with httpx.Client() as client:
                response = client.get(url, timeout=10)
                if response.status_code == 200:
                    config = response.json()
                    self._authorization_endpoint = config.get('authorization_endpoint')
                    self._token_endpoint = config.get('token_endpoint')
                    self._userinfo_endpoint = config.get('userinfo_endpoint')
                    self._end_session_endpoint = config.get('end_session_endpoint')
                    return True
        except Exception as e:
            if self.on_error:
                self.on_error(f"Failed to discover OIDC endpoints: {e}")
        return False

    def _generate_pkce(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge."""
        # Generate code verifier (43-128 chars, URL-safe)
        verifier = secrets.token_urlsafe(32)

        # Generate code challenge (SHA256 hash, base64url encoded)
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()

        return verifier, challenge

    def login(self, timeout: int = 120) -> bool:
        """
        Perform OAuth2 login with PKCE.

        Opens browser for authentication and waits for callback.

        Args:
            timeout: Maximum time to wait for callback in seconds

        Returns:
            True if login successful
        """
        # Try to load existing token first
        if self._load_token_from_storage():
            if not self._token.is_expired():
                self._fetch_user_info()
                return True
            elif self._token.refresh_token:
                if self._refresh_token():
                    return True

        # Discover endpoints
        if not self._authorization_endpoint:
            if not self._discover_endpoints():
                return False

        # Generate PKCE
        verifier, challenge = self._generate_pkce()
        state = secrets.token_urlsafe(16)

        # Build authorization URL
        redirect_uri = f"http://127.0.0.1:{self.config.redirect_port}/callback"
        params = {
            'client_id': self.config.client_id,
            'response_type': 'code',
            'redirect_uri': redirect_uri,
            'scope': self.config.scopes,
            'state': state,
            'code_challenge': challenge,
            'code_challenge_method': 'S256'
        }
        auth_url = f"{self._authorization_endpoint}?{urlencode(params)}"

        # Start callback server
        server = HTTPServer(('127.0.0.1', self.config.redirect_port), CallbackHandler)
        server.auth_code = None
        server.auth_state = None
        server.auth_error = None
        server.timeout = timeout

        # Open browser
        webbrowser.open(auth_url)

        # Wait for callback
        def handle_requests():
            while server.auth_code is None and server.auth_error is None:
                server.handle_request()

        server_thread = threading.Thread(target=handle_requests)
        server_thread.daemon = True
        server_thread.start()
        server_thread.join(timeout=timeout)

        # Check result
        if server.auth_error:
            if self.on_error:
                self.on_error(f"Authentication error: {server.auth_error}")
            return False

        if not server.auth_code:
            if self.on_error:
                self.on_error("Authentication timed out")
            return False

        if server.auth_state != state:
            if self.on_error:
                self.on_error("State mismatch - possible CSRF attack")
            return False

        # Exchange code for token
        return self._exchange_code(server.auth_code, verifier, redirect_uri)

    def _exchange_code(self, code: str, verifier: str, redirect_uri: str) -> bool:
        """Exchange authorization code for tokens."""
        try:
            data = {
                'grant_type': 'authorization_code',
                'client_id': self.config.client_id,
                'code': code,
                'redirect_uri': redirect_uri,
                'code_verifier': verifier
            }

            with httpx.Client() as client:
                response = client.post(
                    self._token_endpoint,
                    data=data,
                    timeout=10
                )

                if response.status_code == 200:
                    token_data = response.json()
                    self._token = TokenInfo(
                        access_token=token_data['access_token'],
                        refresh_token=token_data.get('refresh_token'),
                        expires_at=datetime.now() + timedelta(
                            seconds=token_data.get('expires_in', 3600)
                        ),
                        id_token=token_data.get('id_token')
                    )

                    self._save_token_to_storage()
                    self._fetch_user_info()

                    if self.on_login and self._user_info:
                        self.on_login(self._user_info)

                    return True
                else:
                    if self.on_error:
                        self.on_error(f"Token exchange failed: {response.text}")

        except Exception as e:
            if self.on_error:
                self.on_error(f"Token exchange error: {e}")

        return False

    def _refresh_token(self) -> bool:
        """Refresh the access token."""
        if not self._token or not self._token.refresh_token:
            return False

        try:
            data = {
                'grant_type': 'refresh_token',
                'client_id': self.config.client_id,
                'refresh_token': self._token.refresh_token
            }

            with httpx.Client() as client:
                response = client.post(
                    self._token_endpoint,
                    data=data,
                    timeout=10
                )

                if response.status_code == 200:
                    token_data = response.json()
                    self._token = TokenInfo(
                        access_token=token_data['access_token'],
                        refresh_token=token_data.get(
                            'refresh_token',
                            self._token.refresh_token
                        ),
                        expires_at=datetime.now() + timedelta(
                            seconds=token_data.get('expires_in', 3600)
                        ),
                        id_token=token_data.get('id_token')
                    )

                    self._save_token_to_storage()
                    return True

        except Exception:
            pass

        return False

    def _fetch_user_info(self):
        """Fetch user info from OIDC userinfo endpoint."""
        if not self._token or not self._userinfo_endpoint:
            return

        try:
            with httpx.Client() as client:
                response = client.get(
                    self._userinfo_endpoint,
                    headers={'Authorization': f'Bearer {self._token.access_token}'},
                    timeout=10
                )

                if response.status_code == 200:
                    data = response.json()
                    self._user_info = UserInfo(
                        sub=data['sub'],
                        email=data.get('email'),
                        name=data.get('name'),
                        preferred_username=data.get('preferred_username'),
                        groups=data.get('groups')
                    )

        except Exception:
            pass

    def _save_token_to_storage(self):
        """Save token to secure storage."""
        if not KEYRING_AVAILABLE or not self._token:
            return

        try:
            keyring.set_password(
                self.APP_NAME,
                "oauth_token",
                json.dumps(self._token.to_dict())
            )
        except Exception:
            pass

    def _load_token_from_storage(self) -> bool:
        """Load token from secure storage."""
        if not KEYRING_AVAILABLE:
            return False

        try:
            token_json = keyring.get_password(self.APP_NAME, "oauth_token")
            if token_json:
                self._token = TokenInfo.from_dict(json.loads(token_json))

                # Discover endpoints if needed
                if not self._token_endpoint:
                    self._discover_endpoints()

                return True
        except Exception:
            pass

        return False

    def logout(self):
        """Log out and clear tokens."""
        # Clear stored token
        if KEYRING_AVAILABLE:
            try:
                keyring.delete_password(self.APP_NAME, "oauth_token")
            except Exception:
                pass

        # End session at Authentik (if supported)
        if self._end_session_endpoint and self._token:
            try:
                params = {'id_token_hint': self._token.id_token}
                webbrowser.open(f"{self._end_session_endpoint}?{urlencode(params)}")
            except Exception:
                pass

        self._token = None
        self._user_info = None

        if self.on_logout:
            self.on_logout()

    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        if self._token is None:
            return self._load_token_from_storage()

        if self._token.is_expired():
            return self._refresh_token()

        return True

    def get_user_info(self) -> Optional[UserInfo]:
        """Get current user info."""
        return self._user_info

    def get_access_token(self) -> Optional[str]:
        """Get current access token (auto-refresh if needed)."""
        if not self._token:
            return None

        if self._token.is_expired():
            if not self._refresh_token():
                return None

        return self._token.access_token
