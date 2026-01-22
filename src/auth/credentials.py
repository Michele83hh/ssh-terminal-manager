"""
Credential provider abstraction for local and central credential storage.
"""
from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass

from ..storage.encryption import EncryptionManager

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


@dataclass
class Credential:
    """Represents a credential (username/password or SSH key)."""
    username: str
    password: Optional[str] = None
    ssh_key: Optional[str] = None
    ssh_key_passphrase: Optional[str] = None


class CredentialProvider(ABC):
    """Abstract base class for credential providers."""

    @abstractmethod
    def get_credential(self, identifier: str) -> Optional[Credential]:
        """
        Get credential by identifier.

        Args:
            identifier: Connection name or host identifier

        Returns:
            Credential if found, None otherwise
        """
        pass

    @abstractmethod
    def save_credential(self, identifier: str, credential: Credential) -> bool:
        """
        Save a credential.

        Args:
            identifier: Connection name or host identifier
            credential: Credential to save

        Returns:
            True if saved successfully
        """
        pass

    @abstractmethod
    def delete_credential(self, identifier: str) -> bool:
        """
        Delete a credential.

        Args:
            identifier: Connection name or host identifier

        Returns:
            True if deleted successfully
        """
        pass

    @abstractmethod
    def list_credentials(self) -> list[str]:
        """
        List all stored credential identifiers.

        Returns:
            List of identifiers
        """
        pass


class LocalCredentialProvider(CredentialProvider):
    """
    Local credential storage using encryption.

    Credentials are stored encrypted in the application database.
    """

    def __init__(self, encryption: EncryptionManager):
        self.encryption = encryption
        self._credentials: dict[str, str] = {}  # identifier -> encrypted data

    def get_credential(self, identifier: str) -> Optional[Credential]:
        """Get credential from local encrypted storage."""
        if not self.encryption.is_initialized():
            return None

        encrypted = self._credentials.get(identifier)
        if not encrypted:
            return None

        try:
            data = self.encryption.decrypt_dict(encrypted)
            return Credential(
                username=data.get('username', ''),
                password=data.get('password'),
                ssh_key=data.get('ssh_key'),
                ssh_key_passphrase=data.get('ssh_key_passphrase')
            )
        except Exception:
            return None

    def save_credential(self, identifier: str, credential: Credential) -> bool:
        """Save credential to local encrypted storage."""
        if not self.encryption.is_initialized():
            return False

        try:
            data = {
                'username': credential.username,
                'password': credential.password,
                'ssh_key': credential.ssh_key,
                'ssh_key_passphrase': credential.ssh_key_passphrase
            }
            self._credentials[identifier] = self.encryption.encrypt_dict(data)
            return True
        except Exception:
            return False

    def delete_credential(self, identifier: str) -> bool:
        """Delete credential from local storage."""
        if identifier in self._credentials:
            del self._credentials[identifier]
            return True
        return False

    def list_credentials(self) -> list[str]:
        """List all stored credential identifiers."""
        return list(self._credentials.keys())

    def export_credentials(self) -> dict[str, str]:
        """Export encrypted credentials for backup."""
        return self._credentials.copy()

    def import_credentials(self, credentials: dict[str, str]):
        """Import encrypted credentials from backup."""
        self._credentials.update(credentials)


class AuthentikCredentialProvider(CredentialProvider):
    """
    Credential provider using Authentik LDAP or custom attributes.

    Requires Authentik API access to retrieve stored credentials.
    This is useful for centralized credential management.
    """

    def __init__(
        self,
        authentik_url: str,
        api_token: str,
        ldap_base_dn: Optional[str] = None
    ):
        if not HTTPX_AVAILABLE:
            raise ImportError("httpx package required")

        self.authentik_url = authentik_url.rstrip('/')
        self.api_token = api_token
        self.ldap_base_dn = ldap_base_dn
        self._client = httpx.Client(
            headers={'Authorization': f'Bearer {api_token}'},
            timeout=10
        )

    def get_credential(self, identifier: str) -> Optional[Credential]:
        """
        Get credential from Authentik.

        Looks up credentials stored in user attributes or LDAP.
        """
        try:
            # Try to get from Authentik property mappings or custom attributes
            response = self._client.get(
                f"{self.authentik_url}/api/v3/core/users/",
                params={'search': identifier}
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('results'):
                    user = data['results'][0]
                    attrs = user.get('attributes', {})

                    # Check for SSH credentials in attributes
                    ssh_creds = attrs.get('ssh_credentials', {})
                    if ssh_creds.get(identifier):
                        cred_data = ssh_creds[identifier]
                        return Credential(
                            username=cred_data.get('username', user.get('username', '')),
                            password=cred_data.get('password'),
                            ssh_key=cred_data.get('ssh_key')
                        )

        except Exception:
            pass

        return None

    def save_credential(self, identifier: str, credential: Credential) -> bool:
        """
        Save credential to Authentik.

        Note: This requires appropriate permissions on the Authentik side.
        """
        # Saving credentials to Authentik requires more complex setup
        # This is a placeholder for the actual implementation
        return False

    def delete_credential(self, identifier: str) -> bool:
        """Delete credential from Authentik."""
        return False

    def list_credentials(self) -> list[str]:
        """List available credentials from Authentik."""
        return []

    def close(self):
        """Close HTTP client."""
        self._client.close()


class CompositeCredentialProvider(CredentialProvider):
    """
    Composite provider that checks multiple sources.

    Tries providers in order and returns first match.
    """

    def __init__(self, providers: list[CredentialProvider]):
        self.providers = providers

    def get_credential(self, identifier: str) -> Optional[Credential]:
        """Get credential from first matching provider."""
        for provider in self.providers:
            credential = provider.get_credential(identifier)
            if credential:
                return credential
        return None

    def save_credential(self, identifier: str, credential: Credential) -> bool:
        """Save to first provider that accepts it."""
        for provider in self.providers:
            if provider.save_credential(identifier, credential):
                return True
        return False

    def delete_credential(self, identifier: str) -> bool:
        """Delete from all providers."""
        deleted = False
        for provider in self.providers:
            if provider.delete_credential(identifier):
                deleted = True
        return deleted

    def list_credentials(self) -> list[str]:
        """List credentials from all providers."""
        identifiers = set()
        for provider in self.providers:
            identifiers.update(provider.list_credentials())
        return list(identifiers)
