"""
app/encryption/aes.py
----------------------
Utility wrapper around AES-256-GCM encryption/decryption operations.
Reuses the authoritative implementation in app.security.encryption.
"""

from app.security.encryption import EncryptionManager


class AESCipher:
    """Convenience wrapper around EncryptionManager for AES-256-GCM operations."""

    def __init__(self) -> None:
        self._enc_mgr = EncryptionManager()

    def generate_nonce(self) -> bytes:
        """Generate a random 12-byte nonce for AES-GCM."""
        return self._enc_mgr.generate_nonce()

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Encrypt plaintext bytes with key. Returns (ciphertext, nonce)."""
        if nonce is None:
            nonce = self.generate_nonce()
        ciphertext = self._enc_mgr.encrypt_bytes(plaintext, key, nonce)
        return ciphertext, nonce

    def decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
        """Decrypt ciphertext bytes with key and nonce."""
        return self._enc_mgr.decrypt_bytes(ciphertext, key, nonce)

    def encrypt_vault_key(
        self,
        vault_key: bytes,
        master_key: bytes,
        nonce: bytes,
    ) -> bytes:
        """Encrypt 32-byte vault key with master key."""
        return self._enc_mgr.encrypt_vault_key(vault_key, master_key, nonce)

    def decrypt_vault_key(
        self,
        ciphertext: bytes,
        master_key: bytes,
        nonce: bytes,
    ) -> bytes:
        """Decrypt 32-byte vault key with master key."""
        return self._enc_mgr.decrypt_vault_key(ciphertext, master_key, nonce)
