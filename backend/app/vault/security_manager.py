"""
vault/security_manager.py
--------------------------
Filesystem manager for vault security metadata (``security.json``).

:class:`SecurityMetadataManager` owns every filesystem operation related
to ``security.json``.  Its responsibilities are:

* **Create** -- write a fresh ``security.json`` during vault scaffolding.
* **Read** -- deserialise ``security.json`` for inspection.
* **Validate** -- assert that ``security.json`` exists and is parseable.

Design decisions
----------------
* **Scoped to one vault root** -- the manager is constructed with a
  ``vault_root: Path`` rather than a global base directory.  This keeps
  it stateless and easy to instantiate inline during vault creation.
* **pathlib throughout** -- all path composition uses :class:`~pathlib.Path`
  objects; no string concatenation.
* **Typed exceptions** -- all errors are raised as domain exceptions
  (:class:`~app.core.exceptions.SecurityMetadataNotFoundError`,
  :class:`~app.core.exceptions.SecurityMetadataError`) so the calling
  layer never needs to inspect raw ``OSError`` or ``json.JSONDecodeError``.
* **No cryptography** -- this module never generates keys, derives
  passwords, or performs any encryption.  It is a pure I/O layer.
"""

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
    """
    Handles all filesystem operations for a vault's ``security.json``.

    Parameters
    ----------
    vault_root:
        Absolute path to the vault's root directory (e.g.
        ``vaults/<vault_uuid>/``).  The file ``security.json`` will be
        read from and written to this directory.
    """

    def __init__(self, vault_root: Path) -> None:
        self._vault_root: Path = vault_root
        self._security_path: Path = vault_root / _SECURITY_FILENAME

    def create(self, vault_id: str) -> None:
        """
        Write a fresh ``security.json`` to the vault root.

        Constructs a :class:`~app.vault.security.SecurityMetadata` with
        all default algorithm choices and the current UTC timestamp, then
        serialises it to disk.

        This method is called exactly once per vault, during
        :meth:`~app.vault.vault_manager.VaultManager.create`.

        Parameters
        ----------
        vault_id:
            UUID4 string used only in log and error messages.

        Raises
        ------
        SecurityMetadataError
            If the file cannot be written (permission denied, disk full,
            etc.).
        """
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
        """
        Read and return the current ``security.json`` for this vault.

        Parameters
        ----------
        vault_id:
            UUID4 string used only in log and error messages.

        Returns
        -------
        SecurityMetadata
            The deserialised security metadata as it currently exists
            on disk.

        Raises
        ------
        SecurityMetadataNotFoundError
            If ``security.json`` does not exist in the vault root.
        SecurityMetadataError
            If the file exists but is malformed or unreadable.
        """
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
        """
        Assert that ``security.json`` exists and can be fully parsed.

        This method performs a complete read-and-validate cycle.  It is
        intended to be used by future milestones that need to confirm a
        vault is cryptographically ready before performing sensitive
        operations.

        Parameters
        ----------
        vault_id:
            UUID4 string used only in log and error messages.

        Raises
        ------
        SecurityMetadataNotFoundError
            If ``security.json`` does not exist.
        SecurityMetadataError
            If the file exists but cannot be parsed or has missing fields.
        """
        logger.debug(
            "Validating security.json for vault '%s'", vault_id
        )

        self.read(vault_id)

        logger.debug(
            "security.json validation passed for vault '%s'", vault_id
        )

    def _assert_security_file_present(self, vault_id: str) -> None:
        """
        Raise :class:`SecurityMetadataNotFoundError` if ``security.json``
        is absent from the vault root.

        Uses :meth:`pathlib.Path.is_file` so that a missing file *and*
        a non-file entry (directory, symlink) both trigger the error.

        Logging is intentionally left to the caller so that the action
        context ("read", "validate") appears in the log line rather than
        a generic "missing" message.
        """
        if not self._security_path.is_file():
            raise SecurityMetadataNotFoundError(
                f"security.json not found for vault '{vault_id}'.",
                detail=(
                    f"Vault '{vault_id}' is missing security.json. "
                    "The vault may have been created before this feature "
                    "was introduced, or the file may have been deleted."
                ),
            )
