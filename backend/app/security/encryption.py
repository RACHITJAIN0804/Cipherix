
import base64
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.exceptions import (
    InvalidNonceError,
    VaultKeyDecryptionError,
    VaultKeyEncryptionError,
)
from app.core.logger import get_logger

logger = get_logger(__name__)


NONCE_BYTES: int = 12


_KEY_BYTES: int = 32


_GCM_TAG_BYTES: int = 16


ALGORITHM_LABEL: str = "AES-256-GCM"


class EncryptionManager:

    def generate_nonce(self) -> bytes:
        nonce: bytes = os.urandom(NONCE_BYTES)

        logger.debug(
            "Nonce generated (bytes=%d, source=os_urandom)",
            NONCE_BYTES,
        )

        return nonce

    def encrypt_vault_key(
        self,
        vault_key: bytes,
        master_key: bytes,
        nonce: bytes,
    ) -> bytes:
        self._validate_key_bytes(master_key, "master_key")
        self._validate_key_bytes(vault_key, "vault_key")
        self._validate_nonce(nonce)

        logger.debug(
            "Encrypting Vault Key (algorithm=%s, nonce_bytes=%d, key_bytes=%d)",
            ALGORITHM_LABEL,
            NONCE_BYTES,
            _KEY_BYTES,
        )

        try:
            ciphertext: bytes = AESGCM(master_key).encrypt(
                nonce,
                vault_key,
                None,


            )
        except ValueError as exc:


            logger.error(
                "AES-256-GCM encryption raised ValueError: %s", exc
            )
            raise VaultKeyEncryptionError(
                f"Vault Key encryption failed: {exc}",
                detail=(
                    "AES-256-GCM encryption could not complete.  "
                    "This is an internal server error.  The Vault Key "
                    "was not stored."
                ),
            ) from exc

        logger.info(
            "Vault Key encrypted successfully "
            "(algorithm=%s, ciphertext_bytes=%d)",
            ALGORITHM_LABEL,
            len(ciphertext),
        )

        return ciphertext

    def decrypt_vault_key(
        self,
        ciphertext: bytes,
        master_key: bytes,
        nonce: bytes,
    ) -> bytes:
        self._validate_key_bytes(master_key, "master_key")
        self._validate_nonce(nonce)
        self._validate_ciphertext(ciphertext)

        logger.debug(
            "Decrypting Vault Key (algorithm=%s, nonce_bytes=%d)",
            ALGORITHM_LABEL,
            NONCE_BYTES,
        )

        try:
            vault_key: bytes = AESGCM(master_key).decrypt(
                nonce,
                ciphertext,
                None,
            )
        except InvalidTag:


            logger.warning(
                "Vault Key decryption failed: GCM authentication tag mismatch. "
                "Possible causes: wrong password, tampered key.json, or corrupt nonce."
            )
            raise VaultKeyDecryptionError(
                "Vault Key decryption failed: authentication tag mismatch.",
                detail=(
                    "The GCM authentication tag did not verify.  This usually means "
                    "the password is incorrect.  It may also indicate that key.json "
                    "has been tampered with or is corrupt."
                ),
            )
        except Exception as exc:
            logger.error(
                "Vault Key decryption raised an unexpected error: %s",
                type(exc).__name__,
            )
            raise VaultKeyDecryptionError(
                f"Vault Key decryption failed unexpectedly: {type(exc).__name__}",
                detail=(
                    "An unexpected error occurred during Vault Key decryption.  "
                    "This is an internal server error."
                ),
            ) from exc

        logger.info(
            "Vault Key decrypted and authenticated successfully "
            "(algorithm=%s, key_bytes=%d)",
            ALGORITHM_LABEL,
            len(vault_key),
        )

        return vault_key

    def encrypt_bytes(
        self,
        plaintext: bytes,
        vault_key: bytes,
        nonce: bytes,
    ) -> bytes:
        self._validate_key_bytes(vault_key, "vault_key")
        self._validate_nonce(nonce)

        logger.debug(
            "Encrypting document bytes (algorithm=%s, plaintext_bytes=%d)",
            ALGORITHM_LABEL,
            len(plaintext),
        )

        try:
            ciphertext: bytes = AESGCM(vault_key).encrypt(nonce, plaintext, None)
        except ValueError as exc:
            raise VaultKeyEncryptionError(
                f"Document encryption failed: {exc}",
                detail="AES-256-GCM document encryption could not complete.",
            ) from exc

        logger.info(
            "Document encrypted (algorithm=%s, ciphertext_bytes=%d)",
            ALGORITHM_LABEL,
            len(ciphertext),
        )
        return ciphertext

    def decrypt_bytes(
        self,
        ciphertext: bytes,
        vault_key: bytes,
        nonce: bytes,
    ) -> bytes:
        self._validate_key_bytes(vault_key, "vault_key")
        self._validate_nonce(nonce)
        self._validate_ciphertext(ciphertext)

        try:
            plaintext: bytes = AESGCM(vault_key).decrypt(nonce, ciphertext, None)
        except InvalidTag:
            logger.warning(
                "Document decryption failed: GCM authentication tag mismatch."
            )
            raise VaultKeyDecryptionError(
                "Document decryption failed: authentication tag mismatch.",
                detail=(
                    "The GCM authentication tag did not verify.  The document "
                    "blob may be corrupt, or the wrong Vault Key was supplied."
                ),
            )
        except Exception as exc:
            raise VaultKeyDecryptionError(
                f"Document decryption failed unexpectedly: {type(exc).__name__}",
                detail="An unexpected error occurred during document decryption.",
            ) from exc

        logger.info(
            "Document decrypted (algorithm=%s, plaintext_bytes=%d)",
            ALGORITHM_LABEL,
            len(plaintext),
        )
        return plaintext

    def encode_for_storage(self, data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    def decode_from_storage(self, encoded: str, field_name: str) -> bytes:
        from app.core.exceptions import CorruptedVaultKeyError

        if not isinstance(encoded, str) or not encoded.strip():
            raise CorruptedVaultKeyError(
                f"key.json field '{field_name}' is empty or missing.",
                detail=(
                    f"The '{field_name}' field in key.json must be a non-empty "
                    "Base64 string.  The file may be corrupt."
                ),
            )

        try:
            return base64.b64decode(encoded.encode("ascii"))
        except Exception as exc:
            raise CorruptedVaultKeyError(
                f"key.json field '{field_name}' is not valid Base64.",
                detail=(
                    f"The '{field_name}' field in key.json could not be decoded "
                    f"as Base64: {exc}.  The file may be corrupt."
                ),
            ) from exc

    def compute_sha256(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def validate_envelope(
        self,
        encrypted_vault_key_b64: str,
        nonce_b64: str,
        algorithm: str,
    ) -> None:
        ct_bytes: bytes = self.decode_from_storage(
            encrypted_vault_key_b64, "encrypted_vault_key"
        )
        nonce_bytes: bytes = self.decode_from_storage(nonce_b64, "nonce")


        if len(ct_bytes) < _GCM_TAG_BYTES + 1:
            raise VaultKeyDecryptionError(
                "encrypted_vault_key is too short to contain a GCM tag.",
                detail=(
                    f"The 'encrypted_vault_key' in key.json is {len(ct_bytes)} bytes, "
                    f"which is shorter than the minimum {_GCM_TAG_BYTES + 1} bytes "
                    "(1 plaintext byte + 16-byte GCM authentication tag).  "
                    "The file may be corrupt."
                ),
            )

        if len(nonce_bytes) != NONCE_BYTES:
            raise InvalidNonceError(
                f"nonce in key.json has wrong length: "
                f"expected {NONCE_BYTES} bytes, got {len(nonce_bytes)}.",
                detail=(
                    f"The 'nonce' field in key.json decoded to {len(nonce_bytes)} bytes "
                    f"but AES-256-GCM requires exactly {NONCE_BYTES} bytes (96 bits).  "
                    "The file may be corrupt."
                ),
            )

        if algorithm != ALGORITHM_LABEL:
            raise VaultKeyDecryptionError(
                f"Unsupported algorithm in key.json: '{algorithm}'.",
                detail=(
                    f"key.json specifies algorithm '{algorithm}' but this "
                    f"version of Cipherix only supports '{ALGORITHM_LABEL}'.  "
                    "A schema migration may be required."
                ),
            )

        logger.debug(
            "Encryption envelope validated (algorithm=%s, "
            "ciphertext_bytes=%d, nonce_bytes=%d)",
            algorithm,
            len(ct_bytes),
            len(nonce_bytes),
        )

    @staticmethod
    def _validate_key_bytes(key: bytes, param_name: str) -> None:
        if not isinstance(key, bytes) or len(key) != _KEY_BYTES:
            raise VaultKeyEncryptionError(
                f"'{param_name}' must be exactly {_KEY_BYTES} bytes "
                f"(got {len(key) if isinstance(key, bytes) else type(key).__name__}).",
                detail=(
                    f"AES-256 requires a {_KEY_BYTES}-byte ({_KEY_BYTES * 8}-bit) key.  "
                    f"The supplied '{param_name}' has the wrong length.  "
                    "This is an internal programming error."
                ),
            )

    @staticmethod
    def _validate_nonce(nonce: bytes) -> None:
        if not isinstance(nonce, bytes) or len(nonce) != NONCE_BYTES:
            raise InvalidNonceError(
                f"Nonce must be exactly {NONCE_BYTES} bytes "
                f"(got {len(nonce) if isinstance(nonce, bytes) else type(nonce).__name__}).",
                detail=(
                    f"AES-256-GCM requires a {NONCE_BYTES}-byte ({NONCE_BYTES * 8}-bit) "
                    "nonce per NIST SP 800-38D.  The supplied nonce has the wrong length.  "
                    "This is an internal programming error."
                ),
            )

    @staticmethod
    def _validate_ciphertext(ciphertext: bytes) -> None:
        _MIN_CIPHERTEXT: int = _GCM_TAG_BYTES + 1

        if not isinstance(ciphertext, bytes) or len(ciphertext) < _MIN_CIPHERTEXT:
            raise VaultKeyDecryptionError(
                f"Ciphertext is too short: expected >= {_MIN_CIPHERTEXT} bytes, "
                f"got {len(ciphertext) if isinstance(ciphertext, bytes) else type(ciphertext).__name__}.",
                detail=(
                    f"The provided ciphertext is shorter than the minimum valid "
                    f"AES-256-GCM ciphertext length ({_MIN_CIPHERTEXT} bytes).  "
                    "The stored key.json may be corrupt."
                ),
            )
