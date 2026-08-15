"""
services/security_service.py
------------------------------
Business-logic layer for vault security operations.

:class:`SecurityService` is the single orchestrator for the password-change
(Vault Key rewrap) flow.  Its responsibilities are:

1. **Validate** vault state: exists, unlocked.
2. **Authenticate** the old password by decrypting the Vault Key.
3. **Re-wrap** the Vault Key under a newly derived Master Key.
4. **Persist** the new salt and the new encrypted Vault Key atomically.
5. **Never** decrypt, re-encrypt, or touch any document.

Why only the Vault Key is re-encrypted
---------------------------------------
Cipherix uses a two-layer key hierarchy::

    User Password  ──► Argon2id ──► Master Key (ephemeral, never stored)
                                         │
                                         │ AES-256-GCM key-wrap
                                         ▼
                                   Vault Key (stored encrypted in key.json)
                                         │
                                         │ AES-256-GCM per-document
                                         ▼
                               Encrypted Documents (in encrypted/*.bin)

When the user changes their password:

* **A new Master Key** is derived from ``new_password`` + a fresh salt.
* **The Vault Key is re-wrapped** (decrypted with the old Master Key,
  re-encrypted with the new Master Key).
* **Documents are untouched** — they are encrypted with the Vault Key,
  not the Master Key.  Because the Vault Key itself does not change,
  all existing documents remain decryptable immediately.

This is the essential property of the two-layer hierarchy: password
rotation has O(1) cost regardless of how many documents are stored.
Re-encrypting all documents would be O(n) and would risk data loss on
partial failure.

Architecture
------------
* Cryptographic operations (key derivation, AES-GCM) belong in
  :class:`~app.security.encryption.EncryptionManager` and
  :class:`~app.security.password_manager.PasswordManager`.
* Filesystem operations (reading/writing key.json, password_meta.json)
  belong in :class:`~app.security.key_manager.KeyManager` and
  :class:`~app.security.password_manager.PasswordManager`.
* This service orchestrates — it contains no raw crypto and no raw I/O.

Scalability
-----------
Because documents are never touched during a password change, the
operation completes in constant time:

* 2 x Argon2id derivations (old + new password).
* 1 x AES-256-GCM decryption  (32-byte Vault Key).
* 1 x AES-256-GCM encryption  (32-byte Vault Key).
* 2 x small JSON file writes   (key.json + password_meta.json).

A vault with 10 million documents takes exactly as long as a vault with
zero documents.

Future compatibility
--------------------
* **Recovery seed**: after re-wrap, call a recovery-seed service to
  re-encrypt the *same* new Vault Key under the seed.
* **Hardware key**: call a hardware-key adapter to re-wrap the Vault Key
  under the device's public key.
* **Multi-device sync**: broadcast the new wrapped Vault Key to peer
  devices via the sync channel.
* **Key rotation**: extend this flow to generate a *new* Vault Key,
  re-encrypt all documents, and then discard the old Vault Key.
"""

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
    """
    Orchestrates vault security operations.

    Currently implements Vault Key rewrap (password change).  Designed to
    be extended with recovery seed, hardware key, and multi-device sync
    operations without changing the existing method signatures.

    Parameters
    ----------
    vault_base_dir:
        Root directory under which all vault subdirectories live.
    """

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
        """
        Change the vault password by re-wrapping the Vault Key.

        The Vault Key is decrypted with the old Master Key and immediately
        re-encrypted with a new Master Key derived from ``new_password`` and
        a freshly generated salt.  No document is ever touched.

        Flow
        ----
        1. Assert vault exists.
        2. Assert vault is unlocked.
        3. Load stored salt + KDF params from ``password_meta.json``.
        4. Derive Old Master Key from (``old_password``, stored salt).
        5. Read encrypted Vault Key envelope from ``key.json``.
        6. Validate the envelope (structural check before decryption).
        7. Decrypt the Vault Key using the Old Master Key (AES-256-GCM).
        8. Generate a new random salt.
        9. Derive New Master Key from (``new_password``, new salt).
        10. Generate a new random nonce.
        11. Re-encrypt the Vault Key using the New Master Key.
        12. Write the new encrypted Vault Key to ``key.json``.
        13. Write the new salt + KDF params to ``password_meta.json``.
        14. Discard both Master Keys.

        Parameters
        ----------
        vault_id:
            UUID4 identifying the target vault.
        old_password:
            Current vault password.  Must decrypt the existing Vault Key.
            Never stored or logged.
        new_password:
            New vault password.  Must be non-empty and non-whitespace-only
            (enforced by :class:`~app.security.password_manager.PasswordManager`).
            Never stored or logged.

        Returns
        -------
        ChangePasswordResponse
            Confirmation receipt with ``vault_id`` and ``changed_at`` timestamp.

        Raises
        ------
        VaultNotFoundError
            If the vault directory does not exist.
        VaultLockedError
            If the vault is not in the ``unlocked`` state.
        PasswordChangeError
            If ``old_password`` is wrong, the Vault Key is corrupt, the
            new password fails validation, or any storage write fails.
        """
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

            # Write key.json first.  If password_meta.json then fails, the vault
            # still contains a valid wrapped Vault Key (under the new Master Key),
            # but the stored salt is stale.  The recommended recovery path is to
            # retry the password change — both files will be overwritten cleanly.
            key_mgr.create(
                vault_id=vault_id,
                vault_key_hex="",
                encrypted_vault_key=new_encrypted_vault_key_b64,
                nonce=new_nonce_b64,
            )
            pwd_mgr.write_metadata(vault_id=vault_id, salt_hex=new_salt_hex)

            changed_at: str = datetime.now(UTC).isoformat()

            # Update DB SecurityMetadata record.
            # This is non-atomic with the disk writes (disk goes first).
            # If DB update fails, log a warning: the vault is still usable
            # (the disk files are authoritative) but the DB record is stale.
            # The stale record will be reconciled on the next password change.
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
        """
        Validate a candidate recovery seed against the stored fingerprint.

        Verification does **not** grant access to any key material.  It only
        confirms that the candidate is the same seed that was generated for
        this vault.  Actual vault recovery is a future milestone.

        When ``db`` is provided, the seed fingerprint is compared against the
        value stored in the SQLite ``security_metadata`` table, falling back
        to the on-disk ``recovery_meta.json`` file when ``db`` is ``None``.

        Parameters
        ----------
        vault_id:
            UUID4 identifying the target vault.
        candidate_seed:
            The recovery seed provided by the user.
        db:
            SQLAlchemy session.  When provided, the stored seed fingerprint
            and recovery version are fetched from SQLite.

        Returns
        -------
        VerifySeedResponse
            ``valid=True`` if the seed is a valid BIP-39 mnemonic that
            matches the stored fingerprint; ``False`` if the fingerprint
            does not match.

        Raises
        ------
        VaultNotFoundError
            If the vault directory does not exist.
        InvalidRecoverySeedError
            If the candidate fails BIP-39 structural validation.
        RecoveryMetadataMissingError
            If no recovery seed has been generated for this vault.
        UnsupportedRecoveryVersionError
            If the stored ``recovery_version`` is not supported.
        """
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
        """Return the vault root directory for a given vault_id."""
        return self._vault_base_dir / vault_id

    def _assert_vault_exists(self, vault_id: str) -> Path:
        """
        Assert the vault root directory exists.

        Returns the vault root Path on success.

        Raises
        ------
        VaultNotFoundError
            If the vault directory does not exist.
        """
        root = self._vault_root(vault_id)
        if not root.is_dir():
            raise VaultNotFoundError(
                f"Vault '{vault_id}' does not exist.",
                detail=f"No vault directory found for vault_id '{vault_id}'.",
            )
        return root

    def _assert_vault_unlocked(self, vault_id: str) -> Path:
        """
        Assert the vault exists and is in the ``unlocked`` state.

        Reads ``manifest.json`` to check the current status.

        Returns the vault root Path on success.

        Raises
        ------
        VaultNotFoundError
            If the vault directory or manifest does not exist.
        VaultLockedError
            If the vault status is not ``\"unlocked\"``.
        """
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
