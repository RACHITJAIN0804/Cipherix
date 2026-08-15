"""
security/key_manager.py
-----------------------
Filesystem manager for vault key metadata (``key.json``).

:class:`KeyManager` owns every filesystem operation related to
``key.json``.  Its responsibilities are:

* **Generate** -- produce a cryptographically secure random Vault Key.
* **Create** -- write a fresh ``key.json`` during vault scaffolding.
* **Read** -- deserialise ``key.json`` for inspection.
* **Validate** -- assert that ``key.json`` exists and is structurally sound.

Architecture: why two logical keys?
------------------------------------
Cipherix uses a **two-layer key hierarchy**:

::

    User Password
         │
         │  Argon2id (future milestone)
         ▼
    Master Key  ──── never stored on disk ────► ephemeral in RAM
         │
         │  AES-256-GCM key-wrap (future milestone)
         ▼
    Vault Key  ──── stored (wrapped) in key.json ────► encrypts documents

Master Key
    Derived from the user's password using Argon2id.  Memory-hard and
    salted, making dictionary/rainbow attacks impractical.  Never written
    to disk — it is re-derived on every unlock.

Vault Key
    A 256-bit random value generated once per vault.  It will wrap all
    AES-256-GCM encrypted documents.  Separating it from the Master Key
    means password rotation only re-wraps the single Vault Key rather
    than re-encrypting all documents.

Why passwords are never used directly
--------------------------------------
Raw passwords have low entropy and are predictable.  Argon2id stretches
the password into a 256-bit key with memory-hardness (resisting GPU/ASIC
brute force) and a per-vault salt (preventing precomputed attacks).  The
raw password is discarded immediately after derivation.

Design decisions
----------------
* **Scoped to one vault root** -- :class:`KeyManager` is instantiated
  with a ``vault_root: Path`` (exactly like
  :class:`~app.vault.security_manager.SecurityMetadataManager`).  This
  keeps it stateless and easy to instantiate inline during vault creation.
* **pathlib throughout** -- all path composition uses
  :class:`~pathlib.Path` objects; no string concatenation.
* **Typed exceptions** -- all errors are raised as domain exceptions
  (:class:`~app.core.exceptions.KeyMetadataNotFoundError`,
  :class:`~app.core.exceptions.KeyMetadataError`) so the calling layer
  never needs to inspect raw ``OSError`` or ``json.JSONDecodeError``.
* **Key generation isolated here** -- :meth:`generate_vault_key` is the
  single place in the codebase where raw Vault Key bytes are produced.
  Keeping generation in the I/O manager (not in the data model) respects
  the Single Responsibility Principle: :class:`~app.security.models.KeyMetadata`
  models data; :class:`KeyManager` owns key lifecycle operations.
* **No cryptography** -- this module generates random key *material* via
  :mod:`secrets` (the OS CSPRNG) but performs no encryption, decryption,
  or key derivation.  It is a pure key-generation and I/O layer.
* **Extensible for rotation** -- :meth:`create` accepts a ``vault_key_hex``
  parameter so that a future key-rotation flow can supply a new key without
  changing the public interface.

Extensibility notes
-------------------
* **Argon2id**: a future ``derive_master_key(password, salt)`` helper will
  return a 256-bit key, never stored here.
* **AES-256-GCM wrapping**: a future ``wrap_vault_key(vault_key, master_key)``
  helper will replace the ``"[PENDING_ENCRYPTION]"`` sentinel with real
  ciphertext.  :meth:`create` already accepts ``vault_key_hex`` so the
  caller's API does not change when wrapping is added.
* **Key rotation**: generate a new key, call :meth:`create` again; the
  caller archives the old ``key.json`` to ``key_history/`` before writing
  the new one.
* **Multiple vault versions**: ``key_version`` in
  :class:`~app.security.models.KeyMetadata` allows schema evolution; old
  versions remain readable by branching on that field.
"""

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

# Vault keys are 256 bits (32 bytes) of cryptographically random data.
_VAULT_KEY_BYTES: int = 32


class KeyManager:
    """
    Handles all filesystem operations for a vault's ``key.json``.

    This class is the single authority for generating, reading, writing,
    and validating key metadata.  It intentionally contains no encryption
    logic — it is a pure key-generation and I/O layer.

    Parameters
    ----------
    vault_root:
        Absolute path to the vault's root directory (e.g.
        ``vaults/<vault_uuid>/``).  ``key.json`` will be read from and
        written to this directory.
    """

    def __init__(self, vault_root: Path) -> None:
        self._vault_root: Path = vault_root
        self._key_path: Path = vault_root / _KEY_FILENAME

    def generate_vault_key(self, vault_id: str) -> str:
        """
        Generate a 256-bit cryptographically secure random Vault Key.

        Uses :func:`secrets.token_hex` (backed by the OS CSPRNG) to
        produce 32 bytes (256 bits) of random data, returned as a 64-
        character lowercase hex string.

        This method does **not** store the key — it only generates raw
        key material that the caller must immediately pass to :meth:`create`.
        The caller is responsible for ensuring the raw key does not persist
        beyond the scope in which it is used.

        Parameters
        ----------
        vault_id:
            UUID4 string used in log messages only.

        Returns
        -------
        str
            64-character lowercase hex string (256 bits of key material).
        """
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
        """
        Write a fresh ``key.json`` to the vault root.

        Constructs a :class:`~app.security.models.KeyMetadata` with the
        AES-256-GCM-wrapped Vault Key, serialises it to disk, and returns
        the metadata object for the caller's inspection.

        The raw ``vault_key_hex`` is accepted so that the caller's naming
        convention is unambiguous — callers must still discard the raw key
        immediately after this call.

        Parameters
        ----------
        vault_id:
            UUID4 string used in log and error messages.
        vault_key_hex:
            The raw Vault Key produced by :meth:`generate_vault_key`.
            Accepted here for interface symmetry; the raw bytes must be
            discarded by the caller immediately after this method returns.
        encrypted_vault_key:
            Base64-encoded AES-256-GCM ciphertext of the Vault Key,
            produced by
            :class:`~app.security.encryption.EncryptionManager`.
        nonce:
            Base64-encoded 12-byte nonce used during encryption.

        Returns
        -------
        KeyMetadata
            The newly created, already-persisted metadata object.

        Raises
        ------
        KeyMetadataError
            If the file cannot be written (permission denied, disk full, etc.).
        """
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
        """
        Read and return the current ``key.json`` for this vault.

        Parameters
        ----------
        vault_id:
            UUID4 string used in log and error messages.

        Returns
        -------
        KeyMetadata
            The deserialised key metadata as it currently exists on disk.

        Raises
        ------
        KeyMetadataNotFoundError
            If ``key.json`` does not exist in the vault root.
        KeyMetadataError
            If the file exists but is malformed or unreadable.
        """
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
        """
        Assert that ``key.json`` exists and can be fully parsed.

        Performs a complete read-and-validate cycle.  Intended for use by
        future milestones that need to confirm a vault is
        cryptographically ready before performing sensitive operations.

        Parameters
        ----------
        vault_id:
            UUID4 string used in log and error messages.

        Raises
        ------
        KeyMetadataNotFoundError
            If ``key.json`` does not exist.
        KeyMetadataError
            If the file exists but cannot be parsed or has missing fields.
        """
        logger.debug("Validating key.json for vault '%s'", vault_id)

        metadata: KeyMetadata = self.read(vault_id)

        self._validate_fields(vault_id, metadata)

        logger.debug("key.json validation passed for vault '%s'", vault_id)

    @staticmethod
    def _generate_raw_key() -> str:
        """
        Return 256 bits of cryptographically secure random data as hex.

        Delegates to :func:`secrets.token_hex`, which uses the OS CSPRNG
        (``/dev/urandom`` on Linux/macOS, ``BCryptGenRandom`` on Windows).

        This is a private helper; external callers should use
        :meth:`generate_vault_key` which also logs the generation event.

        Returns
        -------
        str
            64-character lowercase hex string (32 bytes / 256 bits).
        """
        return secrets.token_hex(_VAULT_KEY_BYTES)

    def _assert_key_file_present(self, vault_id: str) -> None:
        """
        Raise :class:`KeyMetadataNotFoundError` if ``key.json`` is absent.

        Uses :meth:`pathlib.Path.is_file` so that a missing file *and*
        a non-file entry (directory, symlink) both trigger the error.

        Logging is left to the caller so that the action context
        (``"read"``, ``"validate"``) appears in the log line.
        """
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
        """
        Assert that every required field in the parsed metadata is a
        non-empty string.

        This is a lightweight structural check — it does not verify
        cryptographic correctness.  The intent is to catch truncated writes
        or hand-edited files before they cause a confusing downstream error.

        The ``isinstance(value, str)`` guard handles the case where a
        field deserialises as ``None`` (e.g. ``"key_id": null`` in JSON).
        Without it, ``value.strip()`` would raise ``AttributeError`` rather
        than the expected :class:`~app.core.exceptions.KeyMetadataError`.

        Parameters
        ----------
        vault_id:
            UUID4 string used in error messages.
        metadata:
            The already-deserialised :class:`~app.security.models.KeyMetadata`.

        Raises
        ------
        KeyMetadataError
            If any required field is absent, ``None``, or empty.
        """
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
