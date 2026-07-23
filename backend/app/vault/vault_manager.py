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
        └── manifest.json   # vault identity & status (written by VaultManifest)

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
    VaultAlreadyExistsError,
    VaultCreationError,
    VaultDeletionError,
    VaultManifestError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.vault.manifest import VaultManifest

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
        Scaffold the vault directory tree and write ``manifest.json``.

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
            If any other filesystem error occurs during creation.
        """
        vault_root = self._base / vault_id

        logger.debug("Creating vault root at %s", vault_root)

        self._create_vault_root(vault_root, vault_id)
        self._create_subdirectories(vault_root, vault_id)
        self._write_manifest(vault_root, manifest, vault_id)

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

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

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
        invalid.  Refusing to delete it protects against accidental removal
        of unrelated directories that happen to share the same path.
        """
        manifest_path = vault_root / "manifest.json"
        if not manifest_path.is_file():
            raise VaultManifestError(
                f"Vault '{vault_id}' is missing manifest.json — refusing deletion.",
                detail=(
                    f"Vault '{vault_id}' exists on disk but has no manifest.json. "
                    "This may indicate a corrupt vault. Deletion was aborted."
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
