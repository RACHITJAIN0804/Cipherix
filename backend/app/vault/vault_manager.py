"""
vault/vault_manager.py
----------------------
Filesystem orchestrator for vault operations.

:class:`VaultManager` is responsible for all filesystem interactions:
creating the directory tree for a new vault, discovering and reading
existing vaults from disk, and permanently deleting vault directories.
It knows nothing about HTTP, Pydantic, or business rules.

Vault layout on disk
--------------------
::

    vaults/
    └── <vault_uuid>/
        ├── encrypted/      # future: AES-encrypted file blobs
        ├── metadata/       # future: per-file metadata records
        ├── temp/           # staging area for in-progress operations
        ├── manifest.json   # vault identity & status (written by VaultManifest)
        └── security.json   # cryptographic algorithm & init state (written by SecurityMetadataManager)

Design decisions
----------------
* **UUID4 as the folder name** — user-supplied names are never used as
  directory names, preventing path-traversal attacks and filesystem
  encoding issues.
* **pathlib throughout** — ``Path`` objects compose cleanly, work on
  all platforms, and avoid the string-concatenation bugs that plague
  ``os.path`` code.
* **Atomic-ish creation** — all ``mkdir`` calls use ``exist_ok=False``
  on the vault root so that a pre-existing UUID (practically impossible
  but theoretically conceivable) raises :class:`VaultAlreadyExistsError`
  before any subdirectory is created.
"""

import shutil
from pathlib import Path

from app.core.exceptions import (
    SecurityMetadataError,
    VaultAlreadyExistsError,
    VaultCreationError,
    VaultDeletionError,
    VaultManifestError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.vault.manifest import VaultManifest
from app.vault.security_manager import SecurityMetadataManager

logger = get_logger(__name__)

# Sub-directories created inside every vault root.
_VAULT_SUBDIRS: tuple[str, ...] = ("encrypted", "metadata", "temp")


class VaultManager:
    """
    Handles all filesystem operations for vault management.

    Parameters
    ----------
    vault_base_dir:
        The top-level ``vaults/`` directory.  Injected rather than
        hard-coded so that tests can point the manager at a temporary
        directory without touching the real filesystem.
    """

    def __init__(self, vault_base_dir: Path) -> None:
        self._base: Path = vault_base_dir

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create(self, vault_id: str, manifest: VaultManifest) -> Path:
        """
        Scaffold the vault directory tree, write ``manifest.json``, and
        write ``security.json``.

        Creation sequence
        -----------------
        1. Create the vault root directory (``<base>/<vault_id>/``).
        2. Create the standard subdirectories (``encrypted/``, ``metadata/``,
           ``temp/``).
        3. Write ``manifest.json`` (vault identity and status).
        4. Write ``security.json`` (cryptographic algorithm and init state).

        Parameters
        ----------
        vault_id:
            UUID4 string used as the vault's folder name.
        manifest:
            Pre-built :class:`~app.vault.manifest.VaultManifest` to
            serialise as ``manifest.json`` inside the vault root.

        Returns
        -------
        Path
            Absolute path to the newly created vault root directory.

        Raises
        ------
        VaultAlreadyExistsError
            If a directory already exists at the target path.
        VaultCreationError
            If any filesystem error occurs during creation (directory
            creation, manifest write, or security metadata write).
        """
        vault_root = self._base / vault_id

        logger.debug("Creating vault root at %s", vault_root)

        self._create_vault_root(vault_root, vault_id)
        self._create_subdirectories(vault_root, vault_id)
        self._write_manifest(vault_root, manifest, vault_id)
        self._write_security_metadata(vault_root, vault_id)

        logger.info("Vault %r scaffolded at %s", manifest.name, vault_root)
        return vault_root

    def delete_vault(self, vault_id: str) -> None:
        """
        Permanently and recursively delete a vault directory from disk.

        Pre-deletion checks
        -------------------
        1. The vault directory (``<base>/<vault_id>/``) must exist.
        2. A ``manifest.json`` must be present inside it.

        These two checks together ensure we never silently delete an
        unrelated directory that somehow shares the path — the manifest
        is the authoritative marker that a path belongs to Cipherix.

        Parameters
        ----------
        vault_id:
            UUID4 string identifying the vault folder to remove.

        Raises
        ------
        VaultNotFoundError
            If the vault directory does not exist.
        VaultManifestError
            If the directory exists but contains no ``manifest.json``
            (invalid vault structure).
        VaultDeletionError
            If the OS refuses to remove the directory tree.
        """
        vault_root = self._base / vault_id

        logger.debug("Attempting to delete vault at %s", vault_root)

        self._assert_vault_exists(vault_root, vault_id)
        self._assert_manifest_present(vault_root, vault_id)
        self._delete_vault_tree(vault_root, vault_id)

        logger.info("Vault '%s' deleted successfully from %s", vault_id, vault_root)

    def list_vaults(self) -> list[VaultManifest]:
        """
        Discover and read all valid vaults from the base directory.

        A vault directory is considered **valid** if it satisfies both:

        1. It is a directory (not a stray file).
        2. It contains a ``manifest.json`` file.

        Directories that fail either criterion are silently skipped.
        Directories whose ``manifest.json`` exists but cannot be parsed
        raise :class:`~app.core.exceptions.VaultManifestError` internally;
        the caller (service layer) is responsible for catching that,
        logging it, and continuing with the remaining vaults.

        Returns
        -------
        list[VaultManifest]
            One :class:`~app.vault.manifest.VaultManifest` per valid vault,
            in filesystem-iteration order (unsorted — the service layer
            is responsible for ordering).
        """
        if not self._base.exists():
            logger.debug("Vault base directory does not exist: %s", self._base)
            return []

        manifests: list[VaultManifest] = []

        for entry in self._base.iterdir():
            if not entry.is_dir():
                logger.debug("Skipping non-directory entry: %s", entry.name)
                continue

            manifest_path = entry / "manifest.json"
            if not manifest_path.is_file():
                logger.debug(
                    "Skipping vault candidate (no manifest.json): %s", entry.name
                )
                continue

            try:
                manifest = self._read_manifest(manifest_path, entry.name)
                manifests.append(manifest)
            except VaultManifestError as exc:
                # One corrupt vault must never abort the entire listing.
                # Log the problem at WARNING level so operators can investigate,
                # then continue processing the remaining vaults.
                logger.warning(
                    "Skipping vault '%s': %s", entry.name, exc.detail
                )
                continue

        logger.debug("Discovered %d valid vault(s) in %s", len(manifests), self._base)
        return manifests

    def read_manifest(self, vault_id: str) -> VaultManifest:
        """
        Read and return the current ``manifest.json`` for a single vault.

        This method is the canonical way for upper layers (e.g.
        :class:`~app.services.vault_service.VaultService`) to inspect a
        vault's state without touching the filesystem path directly.

        Parameters
        ----------
        vault_id:
            UUID4 string that identifies the vault folder.

        Returns
        -------
        VaultManifest
            The deserialised manifest as it currently exists on disk.

        Raises
        ------
        VaultNotFoundError
            If the vault directory does not exist.
        VaultManifestError
            If ``manifest.json`` is absent, unreadable, or malformed JSON.
        """
        return self._load_manifest(vault_id)

    def update_vault_status(self, vault_id: str, new_status: str) -> None:
        """
        Mutate the ``status`` field in ``manifest.json`` and write it back.

        This is the single, authoritative method for changing a vault's
        lock state.  It reads the current manifest, applies the status
        change in memory, then overwrites ``manifest.json`` on disk.

        No encryption, password verification, or key management is
        performed here — this is a pure state-flag update.

        Parameters
        ----------
        vault_id:
            UUID4 string identifying the target vault.
        new_status:
            The new status string to write.  Expected values are
            ``"locked"`` and ``"unlocked"``.

        Raises
        ------
        VaultNotFoundError
            If the vault directory does not exist.
        VaultManifestError
            If ``manifest.json`` is absent, unreadable, malformed, or
            cannot be written back (e.g. permission denied, disk full).
        """
        manifest = self._load_manifest(vault_id)
        manifest_path = self._base / vault_id / "manifest.json"

        logger.debug(
            "Updating vault '%s' status: '%s' -> '%s'",
            vault_id,
            manifest.status,
            new_status,
        )

        manifest.status = new_status

        try:
            manifest.write(manifest_path)
        except OSError as exc:
            raise VaultManifestError(
                f"Failed to write updated manifest for vault '{vault_id}': {exc}",
                detail=(
                    f"OS error while updating manifest.json for vault "
                    f"'{vault_id}': {exc.strerror}. Check filesystem permissions."
                ),
            ) from exc

        logger.debug("manifest.json updated for vault '%s' (status=%s)", vault_id, new_status)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_manifest(self, vault_id: str) -> VaultManifest:
        """
        Assert the vault exists and its manifest is present, then parse it.

        This is the single, shared read pipeline used by both
        :meth:`read_manifest` and :meth:`update_vault_status`.  Centralising
        the three steps here means future changes (e.g. caching, retries)
        only need to be made in one place.

        Parameters
        ----------
        vault_id:
            UUID4 string identifying the target vault.

        Returns
        -------
        VaultManifest
            The deserialised manifest.

        Raises
        ------
        VaultNotFoundError
            If the vault directory does not exist.
        VaultManifestError
            If ``manifest.json`` is absent, unreadable, or malformed JSON.
        """
        vault_root = self._base / vault_id
        manifest_path = vault_root / "manifest.json"

        self._assert_vault_exists(vault_root, vault_id)
        self._assert_manifest_present(vault_root, vault_id)

        return self._read_manifest(manifest_path, vault_id)

    def _assert_vault_exists(self, vault_root: Path, vault_id: str) -> None:
        """Raise :class:`VaultNotFoundError` if the vault directory is absent.

        ``Path.is_dir()`` returns ``False`` for both missing paths *and*
        non-directory entries (files, symlinks), so a single call is
        sufficient to guard against both cases without a TOCTOU split.
        """
        if not vault_root.is_dir():
            raise VaultNotFoundError(
                f"Vault directory not found: {vault_root}",
                detail=f"No vault with ID '{vault_id}' exists.",
            )

    def _assert_manifest_present(self, vault_root: Path, vault_id: str) -> None:
        """
        Raise :class:`VaultManifestError` if ``manifest.json`` is missing.

        A vault directory without a manifest is considered structurally
        invalid.  This guard applies to all operations that require a
        well-formed vault (read, delete, lock, unlock).
        """
        manifest_path = vault_root / "manifest.json"
        if not manifest_path.is_file():
            raise VaultManifestError(
                f"Vault '{vault_id}' is missing manifest.json.",
                detail=(
                    f"Vault '{vault_id}' exists on disk but has no manifest.json. "
                    "This may indicate a corrupt vault."
                ),
            )

    def _delete_vault_tree(self, vault_root: Path, vault_id: str) -> None:
        """
        Recursively remove the vault root directory and all its contents.

        Uses :func:`shutil.rmtree` internally.  On Windows, files inside
        the tree that are marked read-only will cause an ``OSError``;
        this is surfaced as a :class:`VaultDeletionError`.
        """
        try:
            shutil.rmtree(vault_root)
            logger.debug("Vault tree removed at %s", vault_root)
        except OSError as exc:
            raise VaultDeletionError(
                f"Failed to delete vault tree at {vault_root}: {exc}",
                detail=(
                    f"OS error while deleting vault '{vault_id}': {exc.strerror}. "
                    "Check filesystem permissions."
                ),
            ) from exc

    def _create_vault_root(self, vault_root: Path, vault_id: str) -> None:
        """Create the top-level ``<vault_uuid>/`` directory."""
        try:
            # exist_ok=False: raise immediately if the path is already taken.
            vault_root.mkdir(parents=True, exist_ok=False)
        except FileExistsError as exc:
            raise VaultAlreadyExistsError(
                f"Vault directory already exists: {vault_root}",
                detail=f"A vault with ID '{vault_id}' already exists on disk.",
            ) from exc
        except OSError as exc:
            raise VaultCreationError(
                f"Failed to create vault root directory: {vault_root}",
                detail=f"OS error while creating vault '{vault_id}': {exc.strerror}",
            ) from exc

    def _create_subdirectories(self, vault_root: Path, vault_id: str) -> None:
        """Create ``encrypted/``, ``metadata/``, and ``temp/`` inside the vault root."""
        for sub in _VAULT_SUBDIRS:
            target = vault_root / sub
            try:
                target.mkdir(exist_ok=True)
                logger.debug("Created subdirectory %s", target)
            except OSError as exc:
                raise VaultCreationError(
                    f"Failed to create vault subdirectory '{sub}': {target}",
                    detail=(
                        f"OS error while creating '{sub}' for vault "
                        f"'{vault_id}': {exc.strerror}"
                    ),
                ) from exc

    def _write_manifest(
        self, vault_root: Path, manifest: VaultManifest, vault_id: str
    ) -> None:
        """Serialise the manifest to ``manifest.json`` in the vault root."""
        manifest_path = vault_root / "manifest.json"
        try:
            manifest.write(manifest_path)
            logger.debug("Wrote manifest.json at %s", manifest_path)
        except OSError as exc:
            raise VaultCreationError(
                f"Failed to write manifest.json for vault '{vault_id}'",
                detail=f"OS error writing manifest: {exc.strerror}",
            ) from exc

    def _write_security_metadata(self, vault_root: Path, vault_id: str) -> None:
        """
        Write ``security.json`` to the vault root via
        :class:`~app.vault.security_manager.SecurityMetadataManager`.

        Delegates all I/O to :class:`SecurityMetadataManager` and re-wraps
        any :class:`~app.core.exceptions.SecurityMetadataError` as a
        :class:`~app.core.exceptions.VaultCreationError` so that
        :meth:`create` exposes a single, consistent failure type.
        """
        try:
            SecurityMetadataManager(vault_root).create(vault_id)
        except SecurityMetadataError as exc:
            raise VaultCreationError(
                f"Failed to write security.json for vault '{vault_id}': {exc.message}",
                detail=exc.detail,
            ) from exc

    def _read_manifest(
        self, manifest_path: Path, vault_dir_name: str
    ) -> VaultManifest:
        """
        Attempt to deserialise a ``manifest.json`` and return it.

        On any read or parse failure the method raises
        :class:`~app.core.exceptions.VaultManifestError`.  The caller
        (``list_vaults``) is responsible for catching it, logging it, and
        continuing with the next vault.

        Parameters
        ----------
        manifest_path:
            Absolute path to the ``manifest.json`` file.
        vault_dir_name:
            The directory name (vault UUID), used only in error messages.

        Returns
        -------
        VaultManifest
            The deserialised manifest.

        Raises
        ------
        VaultManifestError
            On any I/O or parse error.
        """
        try:
            return VaultManifest.read(manifest_path)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise VaultManifestError(
                f"Cannot read manifest for vault '{vault_dir_name}': {exc}",
                detail=(
                    f"Vault '{vault_dir_name}' has a malformed or unreadable "
                    f"manifest.json and will be skipped."
                ),
            ) from exc
