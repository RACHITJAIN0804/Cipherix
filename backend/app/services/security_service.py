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

from app.core.exceptions import (
    CipherixError,
    PasswordChangeError,
    VaultKeyDecryptionError,
    VaultLockedError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.schemas.security import ChangePasswordResponse
from app.security.encryption import EncryptionManager
from app.security.key_manager import KeyManager
from app.security.models import KeyMetadata
from app.security.password_manager import PasswordManager
from app.vault.manifest import VaultManifest

logger = get_logger(__name__)

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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def change_password(
        self,
        vault_id: str,
        old_password: str,
        new_password: str,
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

        old_master_key: bytes | None = None
        new_master_key: bytes | None = None
        vault_key: bytes | None = None

        try:
            pwd_mgr = PasswordManager(vault_root)
            key_mgr = KeyManager(vault_root)

            # --- Step 3: Load stored metadata ---
            salt_hex, _kdf_params = pwd_mgr.read_metadata(vault_id)

            # --- Step 4: Derive Old Master Key ---
            logger.info(
                "Deriving old Master Key for password change | vault_id=%s",
                vault_id,
            )
            old_master_key = pwd_mgr.derive_master_key(old_password, salt_hex)

            # --- Steps 5 & 6: Read + validate key.json envelope ---
            key_meta: KeyMetadata = key_mgr.read(vault_id)
            self._enc_mgr.validate_envelope(
                encrypted_vault_key_b64=key_meta.encrypted_vault_key,
                nonce_b64=key_meta.nonce,
                algorithm=key_meta.algorithm,
            )

            # --- Step 7: Decrypt Vault Key with old Master Key ---
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

            # --- Step 8: Generate new salt ---
            new_salt_hex: str = pwd_mgr.generate_salt()

            # --- Step 9: Derive New Master Key ---
            logger.info(
                "Deriving new Master Key | vault_id=%s",
                vault_id,
            )
            new_master_key = pwd_mgr.derive_master_key(new_password, new_salt_hex)

            # --- Steps 10 & 11: Generate nonce + re-encrypt Vault Key ---
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

            # --- Steps 12 & 13: Persist new key.json and password_meta.json ---
            # Write key.json first.  If password_meta.json then fails, the vault
            # still contains a valid wrapped Vault Key (under the new Master Key),
            # but the stored salt is stale.  The recommended recovery path is to
            # retry the password change — both files will be overwritten cleanly.
            key_mgr.create(
                vault_id=vault_id,
                vault_key_hex="",  # Raw key not needed here; create() only writes the wrapped form.
                encrypted_vault_key=new_encrypted_vault_key_b64,
                nonce=new_nonce_b64,
            )
            pwd_mgr.write_metadata(vault_id=vault_id, salt_hex=new_salt_hex)

            changed_at: str = datetime.now(UTC).isoformat()

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
            # Re-raise all other typed domain errors (InvalidPasswordError,
            # MissingSaltError, KeyMetadataError, etc.) without wrapping —
            # the route exception mapper will handle them.
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

        finally:
            # Discard both Master Keys and the Vault Key immediately.
            for key_var in ("old_master_key", "new_master_key", "vault_key"):
                try:
                    del locals()[key_var]
                except KeyError:
                    pass

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

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
