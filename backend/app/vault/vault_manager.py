
import shutil
from pathlib import Path

from app.core.exceptions import (
    InvalidKdfParamsError,
    KeyMetadataError,
    SecurityMetadataError,
    VaultAlreadyExistsError,
    VaultCreationError,
    VaultDeletionError,
    VaultManifestError,
    VaultNotFoundError,
    VaultKeyEncryptionError,
)
from app.core.logger import get_logger
from app.security.encryption import EncryptionManager
from app.security.key_manager import KeyManager
from app.security.password_manager import PasswordManager
from app.vault.manifest import VaultManifest
from app.vault.security_manager import SecurityMetadataManager

logger = get_logger(__name__)

_VAULT_SUBDIRS: tuple[str, ...] = ("encrypted", "metadata", "temp")


class VaultManager:

    def __init__(self, vault_base_dir: Path) -> None:
        self._base: Path = vault_base_dir

    def create(
        self,
        vault_id: str,
        manifest: VaultManifest,
        password: str,
    ) -> Path:
        vault_root = self._base / vault_id

        logger.debug("Creating vault root at %s", vault_root)

        self._create_vault_root(vault_root, vault_id)
        self._create_subdirectories(vault_root, vault_id)
        self._write_manifest(vault_root, manifest, vault_id)
        self._write_security_metadata(vault_root, vault_id)


        self._write_key_metadata(vault_root, vault_id, password)

        logger.info("Vault %r scaffolded at %s", manifest.name, vault_root)
        return vault_root


    def delete_vault(self, vault_id: str) -> None:
        vault_root = self._base / vault_id

        logger.debug("Attempting to delete vault at %s", vault_root)

        self._assert_vault_exists(vault_root, vault_id)
        self._assert_manifest_present(vault_root, vault_id)
        self._delete_vault_tree(vault_root, vault_id)

        logger.info("Vault '%s' deleted successfully from %s", vault_id, vault_root)

    def list_vaults(self) -> list[VaultManifest]:
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


                logger.warning(
                    "Skipping vault '%s': %s", entry.name, exc.detail
                )
                continue

        logger.debug("Discovered %d valid vault(s) in %s", len(manifests), self._base)
        return manifests

    def read_manifest(self, vault_id: str) -> VaultManifest:
        return self._load_manifest(vault_id)

    def update_vault_status(self, vault_id: str, new_status: str) -> None:
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

    def _load_manifest(self, vault_id: str) -> VaultManifest:
        vault_root = self._base / vault_id
        manifest_path = vault_root / "manifest.json"

        self._assert_vault_exists(vault_root, vault_id)
        self._assert_manifest_present(vault_root, vault_id)

        return self._read_manifest(manifest_path, vault_id)

    def _assert_vault_exists(self, vault_root: Path, vault_id: str) -> None:
        if not vault_root.is_dir():
            raise VaultNotFoundError(
                f"Vault directory not found: {vault_root}",
                detail=f"No vault with ID '{vault_id}' exists.",
            )

    def _assert_manifest_present(self, vault_root: Path, vault_id: str) -> None:
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
        try:
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
        try:
            SecurityMetadataManager(vault_root).create(vault_id)
        except SecurityMetadataError as exc:
            raise VaultCreationError(
                f"Failed to write security.json for vault '{vault_id}': {exc.message}",
                detail=exc.detail,
            ) from exc

    def _write_key_metadata(self, vault_root: Path, vault_id: str, password: str) -> None:
        from app.core.exceptions import MissingSaltError

        key_mgr = KeyManager(vault_root)
        enc_mgr = EncryptionManager()
        pwd_mgr = PasswordManager(vault_root)

        try:
            vault_key_hex: str = key_mgr.generate_vault_key(vault_id)
            vault_key_bytes: bytes = bytes.fromhex(vault_key_hex)

            salt_hex: str = pwd_mgr.generate_salt()
            master_key: bytes = pwd_mgr.derive_master_key(password, salt_hex)

            nonce: bytes = enc_mgr.generate_nonce()
            ciphertext: bytes = enc_mgr.encrypt_vault_key(
                vault_key=vault_key_bytes,
                master_key=master_key,
                nonce=nonce,
            )

            encrypted_vault_key_b64: str = enc_mgr.encode_for_storage(ciphertext)
            nonce_b64: str = enc_mgr.encode_for_storage(nonce)

            key_mgr.create(
                vault_id=vault_id,
                vault_key_hex=vault_key_hex,
                encrypted_vault_key=encrypted_vault_key_b64,
                nonce=nonce_b64,
            )

            pwd_mgr.write_metadata(vault_id, salt_hex)

        except (KeyMetadataError, VaultKeyEncryptionError, InvalidKdfParamsError,
                MissingSaltError) as exc:
            raise VaultCreationError(
                f"Failed to write key material for vault '{vault_id}': {exc.message}",
                detail=exc.detail,
            ) from exc
        finally:


            try:
                del vault_key_hex
            except NameError:
                pass
            try:
                del vault_key_bytes
            except NameError:
                pass
            try:
                del master_key
            except NameError:
                pass
            try:
                del salt_hex
            except NameError:
                pass
            try:
                del nonce
            except NameError:
                pass
            try:
                del ciphertext
            except NameError:
                pass

    def _read_manifest(
        self, manifest_path: Path, vault_dir_name: str
    ) -> VaultManifest:
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

