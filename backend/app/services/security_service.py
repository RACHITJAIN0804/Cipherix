
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.exceptions import (
    CipherixError,
    PasswordChangeError,
    RecoveryMetadataMissingError,
    VaultKeyDecryptionError,
    VaultLockedError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.database.models import SecurityMetadata as SecurityMetadataRecord
from app.schemas.security import (
    ChangePasswordResponse,
    RecoverySeedResponse,
    VerifySeedResponse,
)
from app.security.encryption import EncryptionManager
from app.security.key_manager import KeyManager
from app.security.models import KeyMetadata
from app.security.password_manager import PasswordManager
from app.security.recovery import RecoveryManager
from app.vault.manifest import VaultManifest

logger = get_logger(__name__)

_STATUS_LOCKED: str = "locked"
_STATUS_UNLOCKED: str = "unlocked"


class SecurityService:

    def __init__(self, vault_base_dir: Path) -> None:
        self._vault_base_dir: Path = vault_base_dir
        self._enc_mgr: EncryptionManager = EncryptionManager()

    def change_password(
        self,
        vault_id: str,
        old_password: str,
        new_password: str,
        db: Session | None = None,
    ) -> ChangePasswordResponse:
        vault_root = self._assert_vault_unlocked(vault_id)

        try:
            pwd_mgr = PasswordManager(vault_root)
            key_mgr = KeyManager(vault_root)

            salt_hex, _kdf_params = pwd_mgr.read_metadata(vault_id)

            logger.info(
                "Deriving old Master Key for password change | vault_id=%s",
                vault_id,
            )
            old_master_key = pwd_mgr.derive_master_key(old_password, salt_hex)

            key_meta: KeyMetadata = key_mgr.read(vault_id)
            self._enc_mgr.validate_envelope(
                encrypted_vault_key_b64=key_meta.encrypted_vault_key,
                nonce_b64=key_meta.nonce,
                algorithm=key_meta.algorithm,
            )

            ct_bytes = self._enc_mgr.decode_from_storage(
                key_meta.encrypted_vault_key, "encrypted_vault_key"
            )
            nonce_bytes = self._enc_mgr.decode_from_storage(
                key_meta.nonce, "nonce"
            )
            vault_key = self._enc_mgr.decrypt_vault_key(
                ciphertext=ct_bytes,
                master_key=old_master_key,
                nonce=nonce_bytes,
            )

            logger.info(
                "Vault Key decrypted successfully (old password verified) | vault_id=%s",
                vault_id,
            )

            new_salt_hex: str = pwd_mgr.generate_salt()

            logger.info(
                "Deriving new Master Key | vault_id=%s",
                vault_id,
            )
            new_master_key = pwd_mgr.derive_master_key(new_password, new_salt_hex)

            new_nonce: bytes = self._enc_mgr.generate_nonce()
            new_encrypted_vault_key: bytes = self._enc_mgr.encrypt_vault_key(
                vault_key=vault_key,
                master_key=new_master_key,
                nonce=new_nonce,
            )

            new_encrypted_vault_key_b64: str = self._enc_mgr.encode_for_storage(
                new_encrypted_vault_key
            )
            new_nonce_b64: str = self._enc_mgr.encode_for_storage(new_nonce)


            key_mgr.create(
                vault_id=vault_id,
                vault_key_hex="",
                encrypted_vault_key=new_encrypted_vault_key_b64,
                nonce=new_nonce_b64,
            )
            pwd_mgr.write_metadata(vault_id=vault_id, salt_hex=new_salt_hex)

            changed_at: str = datetime.now(UTC).isoformat()


            if db is not None:
                try:
                    sec_record = db.get(SecurityMetadataRecord, vault_id)
                    if sec_record is not None:
                        sec_record.encrypted_vault_key = new_encrypted_vault_key_b64
                        sec_record.nonce = new_nonce_b64
                        sec_record.salt = new_salt_hex
                        sec_record.updated_at = datetime.now(UTC)
                        db.commit()
                        logger.info(
                            "SecurityMetadata DB record updated after password change "
                            "| vault_id=%s",
                            vault_id,
                        )
                    else:
                        logger.warning(
                            "SecurityMetadata DB record not found after password change "
                            "— DB may be out of sync | vault_id=%s",
                            vault_id,
                        )
                except SQLAlchemyError as db_exc:
                    db.rollback()
                    logger.warning(
                        "Failed to update SecurityMetadata DB record after password change "
                        "— disk files are current; DB record is stale "
                        "| vault_id=%s | error=%s",
                        vault_id,
                        db_exc,
                    )

            logger.info(
                "Password change complete — Vault Key rewrapped | vault_id=%s | changed_at=%s",
                vault_id,
                changed_at,
            )

            return ChangePasswordResponse(
                vault_id=vault_id,
                changed_at=changed_at,
            )

        except VaultKeyDecryptionError as exc:
            logger.warning(
                "Password change failed — old password incorrect or Vault Key corrupt "
                "| vault_id=%s",
                vault_id,
            )
            raise PasswordChangeError(
                f"Password change failed for vault '{vault_id}': "
                "old password is incorrect or the Vault Key is corrupt.",
                detail=(
                    "The old password did not decrypt the Vault Key.  "
                    "Please verify the old password and try again."
                ),
            ) from exc

        except CipherixError:
            raise

        except Exception as exc:
            logger.error(
                "Unexpected error during password change | vault_id=%s | error=%s",
                vault_id,
                exc,
            )
            raise PasswordChangeError(
                f"Unexpected error during password change for vault '{vault_id}': {exc}",
                detail="An unexpected error occurred during the password change operation.",
            ) from exc

    def generate_recovery_seed(
        self,
        vault_id: str,
        password: str | None = None,
        db: Session | None = None,
    ) -> RecoverySeedResponse:
        vault_root = self._assert_vault_unlocked(vault_id)
        recovery_mgr = RecoveryManager(vault_root)

        seed: str = recovery_mgr.generate_seed(vault_id)
        fingerprint: str = recovery_mgr.compute_fingerprint(seed)
        metadata = recovery_mgr.write_metadata(
            vault_id=vault_id,
            seed_fingerprint=fingerprint,
        )

        if password:
            try:
                pwd_mgr = PasswordManager(vault_root)
                key_mgr = KeyManager(vault_root)
                enc_mgr = EncryptionManager()
                salt_hex, _ = pwd_mgr.read_metadata(vault_id)
                master_key = pwd_mgr.derive_master_key(password, salt_hex)
                key_meta = key_mgr.read(vault_id)
                ct_bytes = enc_mgr.decode_from_storage(key_meta.encrypted_vault_key, "encrypted_vault_key")
                nonce_bytes = enc_mgr.decode_from_storage(key_meta.nonce, "nonce")
                vault_key_bytes = enc_mgr.decrypt_vault_key(ct_bytes, master_key, nonce_bytes)
                recovery_mgr.create_recovery_key(vault_id, vault_key_bytes, seed)
            except Exception as exc:
                logger.warning("Failed to create recovery_key.json during seed generation: %s", exc)

        logger.info(
            "Recovery seed generation complete | vault_id=%s | algorithm=%s",
            vault_id,
            metadata.algorithm,
        )

        if db is not None:
            try:
                sec_record = db.get(SecurityMetadataRecord, vault_id)
                if sec_record is not None:
                    sec_record.seed_fingerprint = fingerprint
                    sec_record.recovery_version = metadata.recovery_version
                    sec_record.updated_at = datetime.now(UTC)
                    db.commit()
                    logger.info(
                        "SecurityMetadata DB record updated with seed fingerprint "
                        "| vault_id=%s",
                        vault_id,
                    )
                else:
                    logger.warning(
                        "SecurityMetadata DB record not found during recovery seed update "
                        "| vault_id=%s",
                        vault_id,
                    )
            except SQLAlchemyError as db_exc:
                db.rollback()
                logger.warning(
                    "Failed to update SecurityMetadata DB record with seed fingerprint "
                    "— disk file is current; DB record is stale "
                    "| vault_id=%s | error=%s",
                    vault_id,
                    db_exc,
                )

        return RecoverySeedResponse(
            vault_id=vault_id,
            seed=seed,
            algorithm=metadata.algorithm,
            word_count=len(seed.split()),
            created_at=metadata.created_at,
        )

    def recover_vault(
        self,
        username: str,
        seed: str,
        new_password: str,
        db: Session | None = None,
    ):
        from app.core.exceptions import (
            AuthError,
            InactiveUserError,
            UserNotFoundError,
        )
        from app.database.models import User, Vault as VaultRecord
        from app.schemas.auth import TokenResponse
        from app.security.jwt_manager import JWTManager

        if db is None:
            raise AuthError("Database session required for recovery.", detail="SQLite DB session is required.")

        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise UserNotFoundError(
                f"User '{username}' not found.",
                detail=f"No registered user found with username '{username}'.",
            )
        if not user.is_active:
            raise InactiveUserError(
                "Account is deactivated.",
                detail=f"Account '{username}' is inactive and cannot perform recovery.",
            )

        vault_record = db.query(VaultRecord).filter(VaultRecord.user_id == user.id).first()
        if vault_record is None:
            raise VaultNotFoundError(
                f"No vault found for user '{username}'.",
                detail=f"User '{username}' has no associated vault record.",
            )

        vault_id = vault_record.id
        vault_root = self._assert_vault_exists(vault_id)
        recovery_mgr = RecoveryManager(vault_root)

        vault_key_bytes: bytes = recovery_mgr.recover_vault_key(vault_id, seed)

        pwd_mgr = PasswordManager(vault_root)
        key_mgr = KeyManager(vault_root)
        enc_mgr = EncryptionManager()

        new_salt_hex: str = pwd_mgr.generate_salt()
        new_master_key: bytes = pwd_mgr.derive_master_key(new_password, new_salt_hex)

        new_nonce_bytes: bytes = enc_mgr.generate_nonce()
        new_encrypted_vk_bytes: bytes = enc_mgr.encrypt_vault_key(
            vault_key=vault_key_bytes,
            master_key=new_master_key,
            nonce=new_nonce_bytes,
        )

        new_encrypted_vk_b64: str = enc_mgr.encode_for_storage(new_encrypted_vk_bytes)
        new_nonce_b64: str = enc_mgr.encode_for_storage(new_nonce_bytes)

        key_mgr.create(
            vault_id=vault_id,
            vault_key_hex="",
            encrypted_vault_key=new_encrypted_vk_b64,
            nonce=new_nonce_b64,
        )
        pwd_mgr.write_metadata(vault_id=vault_id, salt_hex=new_salt_hex)

        manifest_path = vault_root / "manifest.json"
        if manifest_path.is_file():
            try:
                m = VaultManifest.read(manifest_path)
                m.status = _STATUS_LOCKED
                m.write(manifest_path)
            except Exception:
                pass

        try:
            sec_record = db.get(SecurityMetadataRecord, vault_id)
            if sec_record is not None:
                sec_record.encrypted_vault_key = new_encrypted_vk_b64
                sec_record.nonce = new_nonce_b64
                sec_record.salt = new_salt_hex
                sec_record.updated_at = datetime.now(UTC)

            v_record = db.get(VaultRecord, vault_id)
            if v_record is not None:
                v_record.status = _STATUS_LOCKED
                v_record.updated_at = datetime.now(UTC)

            db.commit()
        except SQLAlchemyError as db_exc:
            db.rollback()
            logger.warning("DB update during recovery failed | vault_id=%s | error=%s", vault_id, db_exc)

        jwt_mgr = JWTManager()
        access_token = jwt_mgr.create_access_token(user_id=user.id)
        refresh_token = jwt_mgr.create_refresh_token(user_id=user.id)

        logger.info("Vault recovered successfully via seed | username=%s | vault_id=%s", username, vault_id)
        return TokenResponse(access_token=access_token, refresh_token=refresh_token)

    def verify_recovery_seed(
        self,
        vault_id: str,
        candidate_seed: str,
        db: Session | None = None,
    ) -> VerifySeedResponse:
        vault_root = self._assert_vault_exists(vault_id)
        recovery_mgr = RecoveryManager(vault_root)

        if db is not None:
            sec_record = db.get(SecurityMetadataRecord, vault_id)
            if sec_record is None or sec_record.seed_fingerprint is None:
                raise RecoveryMetadataMissingError(
                    f"No recovery seed fingerprint found in SQLite for vault '{vault_id}'.",
                    detail=(
                        "No recovery seed has been generated for this vault. "
                        "Generate a recovery seed first."
                    ),
                )

            recovery_mgr.validate_seed_format(candidate_seed)

            candidate_fingerprint: str = recovery_mgr.compute_fingerprint(candidate_seed)
            valid: bool = candidate_fingerprint == sec_record.seed_fingerprint
        else:
            valid = recovery_mgr.validate_seed(
                candidate=candidate_seed,
                vault_id=vault_id,
            )

        logger.info(
            "Recovery seed verification | vault_id=%s | valid=%s",
            vault_id,
            valid,
        )

        return VerifySeedResponse(vault_id=vault_id, valid=valid)

    def _vault_root(self, vault_id: str) -> Path:
        return self._vault_base_dir / vault_id

    def _assert_vault_exists(self, vault_id: str) -> Path:
        root = self._vault_root(vault_id)
        if not root.is_dir():
            raise VaultNotFoundError(
                f"Vault '{vault_id}' does not exist.",
                detail=f"No vault directory found for vault_id '{vault_id}'.",
            )
        return root

    def _assert_vault_unlocked(self, vault_id: str) -> Path:
        root = self._assert_vault_exists(vault_id)

        manifest_path = root / "manifest.json"
        try:
            manifest = VaultManifest.read(manifest_path)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise VaultNotFoundError(
                f"Cannot read manifest for vault '{vault_id}': {exc}",
                detail=(
                    f"Vault '{vault_id}' exists on disk but its manifest.json "
                    "could not be read.  The vault may be corrupt."
                ),
            ) from exc

        if manifest.status != _STATUS_UNLOCKED:
            raise VaultLockedError(
                f"Vault '{vault_id}' is locked.  Unlock the vault before changing the password.",
                detail=(
                    f"Vault '{vault_id}' has status '{manifest.status}'.  "
                    "The password can only be changed while the vault is unlocked."
                ),
            )

        return root
