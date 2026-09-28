"""
app/encryption/key_derivation.py
---------------------------------
Utility wrapper around Argon2id Key Derivation Function (KDF).
Reuses the authoritative implementation in app.security.password_manager.
"""

from pathlib import Path

from app.security.kdf_params import KdfParams
from app.security.password_manager import PasswordManager


class KeyDerivationManager:
    """Convenience wrapper around PasswordManager for Argon2id key derivation."""

    def __init__(
        self,
        vault_root: Path | None = None,
        params: KdfParams | None = None,
    ) -> None:
        self._pwd_mgr = PasswordManager(vault_root or Path("."), params=params)

    def generate_salt(self) -> str:
        """Generate a cryptographically secure random salt hex string."""
        return self._pwd_mgr.generate_salt()

    def derive_key(self, secret: str, salt_hex: str) -> bytes:
        """Derive a 32-byte master key from secret and salt using Argon2id."""
        return self._pwd_mgr.derive_master_key(secret, salt_hex)

    def verify_key(self, secret: str, salt_hex: str, expected_key: bytes) -> bool:
        """Verify secret against expected key in constant time."""
        return self._pwd_mgr.verify_password(secret, salt_hex, expected_key)
