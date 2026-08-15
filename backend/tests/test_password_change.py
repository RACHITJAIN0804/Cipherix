"""
tests/test_password_change.py
------------------------------
Unit and integration tests for Vault Key rewrapping (Password Change).

Tests:
1. Successful password change (Master Key re-derivation + Vault Key rewrap).
2. Verification that documents encrypted prior to password change remain decryptable.
3. Verification that old password no longer decrypts the Vault Key post-change.
4. Error handling for incorrect old password (raises PasswordChangeError).
5. Error handling for locked vault (raises VaultLockedError).
6. Error handling for non-existent vault (raises VaultNotFoundError).
"""

import json
import pathlib
import tempfile
import unittest

from app.core.exceptions import (
    PasswordChangeError,
    VaultLockedError,
    VaultNotFoundError,
)
from app.schemas.security import ChangePasswordResponse
from app.security.encryption import EncryptionManager
from app.security.key_manager import KeyManager
from app.security.password_manager import PasswordManager
from app.services.document_service import DocumentService
from app.services.security_service import SecurityService
from app.vault.manifest import VaultManifest
from app.vault.vault_manager import VaultManager


class TestPasswordChange(unittest.TestCase):
    """Test suite for SecurityService.change_password."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_base_dir = pathlib.Path(self.temp_dir.name)
        self.vault_mgr = VaultManager(self.vault_base_dir)
        self.security_service = SecurityService(self.vault_base_dir)
        self.doc_service = DocumentService(self.vault_base_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_and_unlock_vault(
        self, vault_id: str, name: str, password: str
    ) -> pathlib.Path:
        manifest = VaultManifest.create(vault_id=vault_id, name=name)
        self.vault_mgr.create(vault_id=vault_id, manifest=manifest, password=password)

        manifest_path = self.vault_base_dir / vault_id / "manifest.json"
        m = VaultManifest.read(manifest_path)
        m.status = "unlocked"
        m.write(manifest_path)
        return self.vault_base_dir / vault_id

    def test_successful_password_change(self) -> None:
        vault_id = "test-vault-0001"
        old_pass = "OldMasterPassword123!"
        new_pass = "NewMasterPassword456!"

        self._create_and_unlock_vault(vault_id, "Test Vault", old_pass)

        doc_content = b"Confidential document content"
        upload_resp = self.doc_service.upload_document(
            vault_id=vault_id,
            password=old_pass,
            filename="secret.txt",
            content_type="text/plain",
            file_bytes=doc_content,
        )
        doc_id = upload_resp.document_id

        response = self.security_service.change_password(
            vault_id=vault_id,
            old_password=old_pass,
            new_password=new_pass,
        )

        self.assertIsInstance(response, ChangePasswordResponse)
        self.assertEqual(response.vault_id, vault_id)
        self.assertTrue(response.changed_at)

        pwd_mgr = PasswordManager(self.vault_base_dir / vault_id)
        key_mgr = KeyManager(self.vault_base_dir / vault_id)
        enc_mgr = EncryptionManager()

        new_salt, _ = pwd_mgr.read_metadata(vault_id)
        key_meta = key_mgr.read(vault_id)

        old_mk = pwd_mgr.derive_master_key(old_pass, new_salt)
        ct_bytes = enc_mgr.decode_from_storage(
            key_meta.encrypted_vault_key, "encrypted_vault_key"
        )
        nonce_bytes = enc_mgr.decode_from_storage(key_meta.nonce, "nonce")

        with self.assertRaises(Exception):
            enc_mgr.decrypt_vault_key(
                ciphertext=ct_bytes, master_key=old_mk, nonce=nonce_bytes
            )

        decrypted_bytes, metadata = self.doc_service.download_document(
            vault_id=vault_id,
            document_id=doc_id,
            password=new_pass,
        )
        self.assertEqual(decrypted_bytes, doc_content)
        self.assertEqual(metadata.original_filename, "secret.txt")

    def test_incorrect_old_password(self) -> None:
        vault_id = "test-vault-0002"
        old_pass = "CorrectOldPassword123!"
        wrong_pass = "WrongOldPassword123!"
        new_pass = "NewMasterPassword456!"

        self._create_and_unlock_vault(vault_id, "Test Vault 2", old_pass)

        with self.assertRaises(PasswordChangeError):
            self.security_service.change_password(
                vault_id=vault_id,
                old_password=wrong_pass,
                new_password=new_pass,
            )

    def test_locked_vault(self) -> None:
        vault_id = "test-vault-0003"
        old_pass = "OldMasterPassword123!"
        new_pass = "NewMasterPassword456!"

        manifest = VaultManifest.create(vault_id=vault_id, name="Locked Vault")
        self.vault_mgr.create(vault_id=vault_id, manifest=manifest, password=old_pass)

        with self.assertRaises(VaultLockedError):
            self.security_service.change_password(
                vault_id=vault_id,
                old_password=old_pass,
                new_password=new_pass,
            )

    def test_nonexistent_vault(self) -> None:
        with self.assertRaises(VaultNotFoundError):
            self.security_service.change_password(
                vault_id="nonexistent-uuid",
                old_password="pass1",
                new_password="pass2",
            )


if __name__ == "__main__":
    unittest.main()
