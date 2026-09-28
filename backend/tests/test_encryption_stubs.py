"""
tests/test_encryption_stubs.py
--------------------------------
Unit tests for the completed app.encryption utility wrappers:
- app.encryption.seed_phrase.SeedPhraseManager
- app.encryption.key_derivation.KeyDerivationManager
- app.encryption.aes.AESCipher
"""

import unittest
import os
from app.core.exceptions import InvalidRecoverySeedError, VaultKeyDecryptionError
from app.encryption.seed_phrase import SeedPhraseManager
from app.encryption.key_derivation import KeyDerivationManager
from app.encryption.aes import AESCipher


class TestSeedPhraseManager(unittest.TestCase):
    def setUp(self) -> None:
        self.mgr = SeedPhraseManager()

    def test_generate_seed_returns_16_words(self) -> None:
        seed = self.mgr.generate_seed()
        words = seed.split()
        self.assertEqual(len(words), 16)

    def test_generated_seed_validates_successfully(self) -> None:
        seed = self.mgr.generate_seed()
        self.mgr.validate_seed(seed)  # Should not raise

    def test_invalid_word_count_rejected(self) -> None:
        seed = self.mgr.generate_seed()
        short_seed = " ".join(seed.split()[:12])
        with self.assertRaises(InvalidRecoverySeedError):
            self.mgr.validate_seed(short_seed)

    def test_invalid_words_rejected(self) -> None:
        fake_seed = " ".join(["invalidword"] * 16)
        with self.assertRaises(InvalidRecoverySeedError):
            self.mgr.validate_seed(fake_seed)

    def test_compute_fingerprint_deterministic_and_16_hex(self) -> None:
        seed = self.mgr.generate_seed()
        fp1 = self.mgr.compute_fingerprint(seed)
        fp2 = self.mgr.compute_fingerprint(seed)
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 16)


class TestKeyDerivationManager(unittest.TestCase):
    def setUp(self) -> None:
        self.kdf = KeyDerivationManager()

    def test_generate_salt_returns_hex_string(self) -> None:
        salt = self.kdf.generate_salt()
        self.assertIsInstance(salt, str)
        self.assertEqual(len(salt), 64)  # 32 bytes = 64 hex chars

    def test_derive_key_is_deterministic(self) -> None:
        salt = self.kdf.generate_salt()
        key1 = self.kdf.derive_key("SecretPassword123!", salt)
        key2 = self.kdf.derive_key("SecretPassword123!", salt)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)

    def test_derive_key_different_salts_produce_different_keys(self) -> None:
        salt1 = self.kdf.generate_salt()
        salt2 = self.kdf.generate_salt()
        key1 = self.kdf.derive_key("SecretPassword123!", salt1)
        key2 = self.kdf.derive_key("SecretPassword123!", salt2)
        self.assertNotEqual(key1, key2)

    def test_verify_key_returns_true_for_matching_secret(self) -> None:
        salt = self.kdf.generate_salt()
        key = self.kdf.derive_key("SecretPassword123!", salt)
        self.assertTrue(self.kdf.verify_key("SecretPassword123!", salt, key))

    def test_verify_key_returns_false_for_wrong_secret(self) -> None:
        salt = self.kdf.generate_salt()
        key = self.kdf.derive_key("SecretPassword123!", salt)
        self.assertFalse(self.kdf.verify_key("WrongPassword123!", salt, key))


class TestAESCipher(unittest.TestCase):
    def setUp(self) -> None:
        self.aes = AESCipher()
        self.key = os.urandom(32)

    def test_generate_nonce_returns_12_bytes(self) -> None:
        nonce = self.aes.generate_nonce()
        self.assertEqual(len(nonce), 12)

    def test_encrypt_decrypt_bytes_roundtrip(self) -> None:
        data = b"Cipherix top secret document content"
        ct, nonce = self.aes.encrypt(data, self.key)
        self.assertNotEqual(ct, data)

        decrypted = self.aes.decrypt(ct, self.key, nonce)
        self.assertEqual(decrypted, data)

    def test_fresh_nonces_per_encryption(self) -> None:
        data = b"Same content"
        ct1, nonce1 = self.aes.encrypt(data, self.key)
        ct2, nonce2 = self.aes.encrypt(data, self.key)
        self.assertNotEqual(nonce1, nonce2)
        self.assertNotEqual(ct1, ct2)

    def test_wrong_key_fails_decryption(self) -> None:
        data = b"Secret text"
        ct, nonce = self.aes.encrypt(data, self.key)
        wrong_key = os.urandom(32)
        with self.assertRaises(VaultKeyDecryptionError):
            self.aes.decrypt(ct, wrong_key, nonce)

    def test_encrypt_decrypt_vault_key_roundtrip(self) -> None:
        vault_key = os.urandom(32)
        master_key = os.urandom(32)
        nonce = self.aes.generate_nonce()

        ct = self.aes.encrypt_vault_key(vault_key, master_key, nonce)
        recovered_vk = self.aes.decrypt_vault_key(ct, master_key, nonce)
        self.assertEqual(recovered_vk, vault_key)


if __name__ == "__main__":
    unittest.main()
