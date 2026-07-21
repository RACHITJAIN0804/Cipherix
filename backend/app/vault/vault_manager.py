"""
vault/vault_manager.py
----------------------
Filesystem orchestrator for vault creation.

:class:`VaultManager` is responsible for *one thing only*: turning an
abstract "create a vault" instruction into a concrete directory tree on
disk.  It knows nothing about HTTP, Pydantic, or business rules.

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

from pathlib import Path

from app.core.exceptions import VaultAlreadyExistsError, VaultCreationError
from app.core.logger import get_logger
from app.vault.manifest import VaultManifest

logger = get_logger(__name__)

# Sub-directories created inside every vault root.
_VAULT_SUBDIRS: tuple[str, ...] = ("encrypted", "metadata", "temp")


class VaultManager:
    """
    Handles all filesystem operations required to create a vault.

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

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

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
