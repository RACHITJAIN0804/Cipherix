
import secrets
from pathlib import Path

from app.core.exceptions import (
    KeyMetadataError,
    KeyMetadataNotFoundError,
)
from app.core.logger import get_logger
from app.security.models import KeyMetadata

logger = get_logger(__name__)

_KEY_FILENAME: str = "key.json"


_VAULT_KEY_BYTES: int = 32


class KeyManager:

    def __init__(self, vault_root: Path) -> None:
        self._vault_root: Path = vault_root
        self._key_path: Path = vault_root / _KEY_FILENAME

    def generate_vault_key(self, vault_id: str) -> str:
        vault_key_hex: str = self._generate_raw_key()

        logger.debug(
            "Vault key generated for vault '%s' "
            "(algorithm=AES-256-GCM, key_bytes=%d, source=os_csprng)",
            vault_id,
            _VAULT_KEY_BYTES,
        )

        return vault_key_hex

    def create(
        self,
        vault_id: str,
        vault_key_hex: str,
        encrypted_vault_key: str,
        nonce: str,
    ) -> KeyMetadata:
        logger.debug(
            "Writing key.json for vault '%s' at %s",
            vault_id,
            self._key_path,
        )

        metadata: KeyMetadata = KeyMetadata.create(
            encrypted_vault_key=encrypted_vault_key,
            nonce=nonce,
        )

        try:
            metadata.write(self._key_path)
        except OSError as exc:
            raise KeyMetadataError(
                f"Failed to write key.json for vault '{vault_id}': {exc}",
                detail=(
                    f"OS error while creating key.json for vault "
                    f"'{vault_id}': {exc.strerror}. "
                    "Check filesystem permissions."
                ),
            ) from exc

        logger.info(
            "key.json created for vault '%s' "
            "(key_id=%s, algorithm=%s, key_version=%s, status=%s)",
            vault_id,
            metadata.key_id,
            metadata.algorithm,
            metadata.key_version,
            metadata.status,
        )

        return metadata

    def read(self, vault_id: str) -> KeyMetadata:
        try:
            self._assert_key_file_present(vault_id)
        except KeyMetadataNotFoundError:
            logger.warning(
                "Read failed: key.json missing for vault '%s' at %s",
                vault_id,
                self._key_path,
            )
            raise

        try:
            return KeyMetadata.read(self._key_path)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise KeyMetadataError(
                f"Cannot read key.json for vault '{vault_id}': {exc}",
                detail=(
                    f"Vault '{vault_id}' has a malformed or unreadable "
                    f"key.json: {exc}"
                ),
            ) from exc

    def validate(self, vault_id: str) -> None:
        logger.debug("Validating key.json for vault '%s'", vault_id)

        metadata: KeyMetadata = self.read(vault_id)

        self._validate_fields(vault_id, metadata)

        logger.debug("key.json validation passed for vault '%s'", vault_id)

    @staticmethod
    def _generate_raw_key() -> str:
        return secrets.token_hex(_VAULT_KEY_BYTES)

    def _assert_key_file_present(self, vault_id: str) -> None:
        if not self._key_path.is_file():
            raise KeyMetadataNotFoundError(
                f"key.json not found for vault '{vault_id}'.",
                detail=(
                    f"Vault '{vault_id}' is missing key.json. "
                    "The vault may have been created before key management "
                    "was introduced, or the file may have been deleted."
                ),
            )

    def _validate_fields(self, vault_id: str, metadata: KeyMetadata) -> None:
        required_fields: dict[str, object] = {
            "key_version": metadata.key_version,
            "algorithm": metadata.algorithm,
            "created_at": metadata.created_at,
            "status": metadata.status,
            "encrypted_vault_key": metadata.encrypted_vault_key,
            "key_id": metadata.key_id,
            "nonce": metadata.nonce,
        }

        for field_name, value in required_fields.items():
            if not isinstance(value, str) or not value.strip():
                logger.warning(
                    "key.json validation failed for vault '%s': "
                    "field '%s' is missing, null, or empty.",
                    vault_id,
                    field_name,
                )
                raise KeyMetadataError(
                    f"key.json for vault '{vault_id}' has an invalid "
                    f"required field: '{field_name}'.",
                    detail=(
                        f"The field '{field_name}' in key.json for vault "
                        f"'{vault_id}' must be a non-empty string. "
                        "The file may be corrupt or have been modified externally."
                    ),
                )
