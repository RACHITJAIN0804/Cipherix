
from pathlib import Path

from app.core.exceptions import (
    SecurityMetadataError,
    SecurityMetadataNotFoundError,
)
from app.core.logger import get_logger
from app.vault.security import SecurityMetadata

logger = get_logger(__name__)

_SECURITY_FILENAME: str = "security.json"


class SecurityMetadataManager:

    def __init__(self, vault_root: Path) -> None:
        self._vault_root: Path = vault_root
        self._security_path: Path = vault_root / _SECURITY_FILENAME

    def create(self, vault_id: str) -> None:
        logger.debug(
            "Writing security.json for vault '%s' at %s",
            vault_id,
            self._security_path,
        )

        metadata = SecurityMetadata.create()

        try:
            metadata.write(self._security_path)
        except OSError as exc:
            raise SecurityMetadataError(
                f"Failed to write security.json for vault '{vault_id}': {exc}",
                detail=(
                    f"OS error while creating security.json for vault "
                    f"'{vault_id}': {exc.strerror}. Check filesystem permissions."
                ),
            ) from exc

        logger.info(
            "security.json created for vault '%s' "
            "(algorithm=%s, key_derivation=%s, status=%s)",
            vault_id,
            metadata.algorithm,
            metadata.key_derivation,
            metadata.status,
        )

    def read(self, vault_id: str) -> SecurityMetadata:
        try:
            self._assert_security_file_present(vault_id)
        except SecurityMetadataNotFoundError:
            logger.warning(
                "Read failed: security.json missing for vault '%s' at %s",
                vault_id,
                self._security_path,
            )
            raise

        try:
            return SecurityMetadata.read(self._security_path)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise SecurityMetadataError(
                f"Cannot read security.json for vault '{vault_id}': {exc}",
                detail=(
                    f"Vault '{vault_id}' has a malformed or unreadable "
                    f"security.json: {exc}"
                ),
            ) from exc

    def validate(self, vault_id: str) -> None:
        logger.debug(
            "Validating security.json for vault '%s'", vault_id
        )

        self.read(vault_id)

        logger.debug(
            "security.json validation passed for vault '%s'", vault_id
        )

    def _assert_security_file_present(self, vault_id: str) -> None:
        if not self._security_path.is_file():
            raise SecurityMetadataNotFoundError(
                f"security.json not found for vault '{vault_id}'.",
                detail=(
                    f"Vault '{vault_id}' is missing security.json. "
                    "The vault may have been created before this feature "
                    "was introduced, or the file may have been deleted."
                ),
            )
