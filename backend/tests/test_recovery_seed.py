"""
tests/test_recovery_seed.py
----------------------------
Unit and integration tests for BIP-39 Recovery Seed generation and verification.

Covers:
1. Valid seed generation (word count, BIP-39 validity, fingerprint uniqueness).
2. Metadata generation and persistence.
3. Valid seed verification (correct seed -> valid=True).
4. Wrong seed verification (different valid BIP-39 seed -> valid=False).
5. Invalid seed detection (wrong word count, non-BIP39 words, bad checksum).
6. Recovery metadata missing error.
7. Full SecurityService integration (generate + verify round-trip).
"""

import json
import pathlib
import tempfile
import unittest

from mnemonic import Mnemonic

from app.core.exceptions import (
    InvalidRecoverySeedError,
    RecoveryMetadataMissingError,
)
from app.schemas.security import RecoverySeedResponse, VerifySeedResponse
from app.security.recovery import (
    RECOVERY_VERSION,
    SEED_WORD_COUNT,
    RecoveryManager,
    RecoveryMetadata,
    _RECOVERY_ALGORITHM,
)
from app.services.security_service import SecurityService
from app.vault.manifest import VaultManifest
from app.vault.vault_manager import VaultManager


class TestRecoveryMetadata(unittest.TestCase):
    """Test RecoveryMetadata dataclass serialisation."""

    def test_to_dict_contains_required_fields(self) -> None:
        meta = RecoveryMetadata(
            created_at="2026-08-07T00:00:00+00:00",
            seed_fingerprint="abcdef1234567890",
        )
        d = meta.to_dict()
        self.assertIn("recovery_version", d)
        self.assertIn("algorithm", d)
        self.assertIn("created_at", d)
        self.assertIn("checksum_version", d)
        self.assertIn("seed_fingerprint", d)

    def test_defaults_are_correct(self) -> None:
        meta = RecoveryMetadata(
            created_at="2026-08-07T00:00:00+00:00",
            seed_fingerprint="abcdef1234567890",
        )
        self.assertEqual(meta.recovery_version, RECOVERY_VERSION)
        self.assertEqual(meta.algorithm, _RECOVERY_ALGORITHM)

    def test_write_and_read_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            path = pathlib.Path(t) / "recovery_meta.json"
            meta = RecoveryMetadata(
                created_at="2026-08-07T00:00:00+00:00",
                seed_fingerprint="deadbeef12345678",
            )
            meta.write(path)

            loaded = RecoveryMetadata.read(path)
            self.assertEqual(loaded.seed_fingerprint, meta.seed_fingerprint)
            self.assertEqual(loaded.recovery_version, meta.recovery_version)
            self.assertEqual(loaded.algorithm, meta.algorithm)


class TestRecoveryManager(unittest.TestCase):
    """Unit tests for RecoveryManager methods."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_root = pathlib.Path(self.temp_dir.name)
        self.manager = RecoveryManager(self.vault_root)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_generate_seed_has_correct_word_count(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        self.assertEqual(len(seed.split()), SEED_WORD_COUNT)

    def test_generate_seed_is_valid_bip39(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        mnemo = Mnemonic("english")
        self.assertTrue(mnemo.check(seed))

    def test_generate_seed_is_unique(self) -> None:
        seeds = {self.manager.generate_seed("test-vault-001") for _ in range(5)}
        self.assertEqual(len(seeds), 5, "Two consecutive seeds must be different")

    def test_compute_fingerprint_is_deterministic(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        fp1 = self.manager.compute_fingerprint(seed)
        fp2 = self.manager.compute_fingerprint(seed)
        self.assertEqual(fp1, fp2)

    def test_compute_fingerprint_is_16_hex_chars(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        fp = self.manager.compute_fingerprint(seed)
        self.assertEqual(len(fp), 16)
        int(fp, 16)

    def test_compute_fingerprint_is_case_insensitive(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        fp_lower = self.manager.compute_fingerprint(seed.lower())
        fp_upper = self.manager.compute_fingerprint(seed.upper())
        self.assertEqual(fp_lower, fp_upper)

    def test_write_and_read_metadata(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        fingerprint = self.manager.compute_fingerprint(seed)
        meta = self.manager.write_metadata("test-vault-001", fingerprint)

        self.assertEqual(meta.seed_fingerprint, fingerprint)
        self.assertTrue((self.vault_root / "recovery_meta.json").is_file())

        reloaded = self.manager.read_metadata("test-vault-001")
        self.assertEqual(reloaded.seed_fingerprint, fingerprint)

    def test_metadata_does_not_contain_seed(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        fingerprint = self.manager.compute_fingerprint(seed)
        self.manager.write_metadata("test-vault-001", fingerprint)

        raw = (self.vault_root / "recovery_meta.json").read_text(encoding="utf-8")
        for word in seed.split():
            self.assertNotIn(f'"{word}"', raw, f"Seed word '{word}' found in metadata file!")

    def test_validate_seed_correct_returns_true(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        fingerprint = self.manager.compute_fingerprint(seed)
        self.manager.write_metadata("test-vault-001", fingerprint)

        result = self.manager.validate_seed(seed, "test-vault-001")
        self.assertTrue(result)

    def test_validate_seed_wrong_returns_false(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        fingerprint = self.manager.compute_fingerprint(seed)
        self.manager.write_metadata("test-vault-001", fingerprint)

        different_seed = self.manager.generate_seed("test-vault-001")
        while different_seed == seed:
            different_seed = self.manager.generate_seed("test-vault-001")

        result = self.manager.validate_seed(different_seed, "test-vault-001")
        self.assertFalse(result)

    def test_validate_seed_wrong_word_count_raises(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        fingerprint = self.manager.compute_fingerprint(seed)
        self.manager.write_metadata("test-vault-001", fingerprint)

        short_seed = " ".join(seed.split()[:12])
        with self.assertRaises(InvalidRecoverySeedError):
            self.manager.validate_seed(short_seed, "test-vault-001")

    def test_validate_seed_invalid_words_raises(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        fingerprint = self.manager.compute_fingerprint(seed)
        self.manager.write_metadata("test-vault-001", fingerprint)

        fake_seed = " ".join(["notaword"] * SEED_WORD_COUNT)
        with self.assertRaises(InvalidRecoverySeedError):
            self.manager.validate_seed(fake_seed, "test-vault-001")

    def test_validate_seed_no_metadata_raises(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        with self.assertRaises(RecoveryMetadataMissingError):
            self.manager.validate_seed(seed, "test-vault-001")

    def test_has_recovery_seed_false_before_generation(self) -> None:
        self.assertFalse(self.manager.has_recovery_seed())

    def test_has_recovery_seed_true_after_generation(self) -> None:
        seed = self.manager.generate_seed("test-vault-001")
        fp = self.manager.compute_fingerprint(seed)
        self.manager.write_metadata("test-vault-001", fp)
        self.assertTrue(self.manager.has_recovery_seed())


class TestSecurityServiceRecovery(unittest.TestCase):
    """Integration tests for SecurityService recovery seed methods."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_base_dir = pathlib.Path(self.temp_dir.name)
        self.vault_mgr = VaultManager(self.vault_base_dir)
        self.security_service = SecurityService(self.vault_base_dir)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _create_and_unlock_vault(self, vault_id: str, password: str) -> None:
        manifest = VaultManifest.create(vault_id=vault_id, name="Recovery Test Vault")
        self.vault_mgr.create(vault_id=vault_id, manifest=manifest, password=password)
        manifest_path = self.vault_base_dir / vault_id / "manifest.json"
        m = VaultManifest.read(manifest_path)
        m.status = "unlocked"
        m.write(manifest_path)

    def test_generate_recovery_seed_returns_response(self) -> None:
        vault_id = "recovery-test-0001"
        self._create_and_unlock_vault(vault_id, "VaultPassword123!")

        result = self.security_service.generate_recovery_seed(vault_id)

        self.assertIsInstance(result, RecoverySeedResponse)
        self.assertEqual(result.vault_id, vault_id)
        self.assertEqual(result.word_count, SEED_WORD_COUNT)
        self.assertEqual(len(result.seed.split()), SEED_WORD_COUNT)
        self.assertIn("BIP39", result.algorithm)

    def test_generate_seed_writes_metadata_not_seed(self) -> None:
        vault_id = "recovery-test-0002"
        self._create_and_unlock_vault(vault_id, "VaultPassword123!")

        result = self.security_service.generate_recovery_seed(vault_id)

        meta_path = self.vault_base_dir / vault_id / "recovery_meta.json"
        self.assertTrue(meta_path.is_file())
        raw = meta_path.read_text(encoding="utf-8")
        for word in result.seed.split():
            self.assertNotIn(word, raw)

    def test_verify_correct_seed_returns_valid_true(self) -> None:
        vault_id = "recovery-test-0003"
        self._create_and_unlock_vault(vault_id, "VaultPassword123!")

        gen = self.security_service.generate_recovery_seed(vault_id)
        verify = self.security_service.verify_recovery_seed(vault_id, gen.seed)

        self.assertIsInstance(verify, VerifySeedResponse)
        self.assertTrue(verify.valid)

    def test_verify_wrong_seed_returns_valid_false(self) -> None:
        vault_id = "recovery-test-0004"
        self._create_and_unlock_vault(vault_id, "VaultPassword123!")

        self.security_service.generate_recovery_seed(vault_id)

        other_mgr = RecoveryManager(self.vault_base_dir / vault_id)
        wrong_seed = other_mgr.generate_seed("other-vault")

        verify = self.security_service.verify_recovery_seed(vault_id, wrong_seed)
        self.assertFalse(verify.valid)

    def test_verify_invalid_bip39_seed_raises(self) -> None:
        vault_id = "recovery-test-0005"
        self._create_and_unlock_vault(vault_id, "VaultPassword123!")
        self.security_service.generate_recovery_seed(vault_id)

        with self.assertRaises(InvalidRecoverySeedError):
            self.security_service.verify_recovery_seed(vault_id, "invalid seed words")


if __name__ == "__main__":
    unittest.main()
