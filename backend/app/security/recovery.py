"""
security/recovery.py
---------------------
BIP-39 Recovery Seed generation and metadata management for Cipherix.

This module is the single authority for all recovery seed operations.

BIP-39 background
-----------------
BIP-39 (Bitcoin Improvement Proposal 39) defines a standard for encoding
cryptographic entropy as a human-readable sequence of English words, making
it practical for users to write down, transcribe, and store securely.

The encoding works as follows:

1. **Entropy generation**: The OS CSPRNG produces N bits of random entropy.
   Cipherix uses 256 bits, the highest BIP-39 security level.

2. **Checksum**: The first `ENT/32` bits of SHA-256(entropy) are appended.
   For 256-bit entropy, this adds 8 bits, giving 264 bits total.

3. **Word encoding**: The 264 bits are split into 24 groups of 11 bits.
   Each 11-bit value (0-2047) indexes one word from the 2048-word BIP-39
   English wordlist, producing a 24-word mnemonic.

4. **Validation**: Any BIP-39 mnemonic can be independently verified because
   the checksum is re-derived and compared against the embedded checksum bits.

Why BIP-39?
    * Industry-standard (Ledger, Trezor, MetaMask, every major hardware wallet).
    * Built-in checksum allows typo detection without a round-trip to the server.
    * Human-readable — users can write it on paper without transcription errors.
    * Language-independent — future localisation can add wordlists for other languages.
    * Deterministic — the same entropy always produces the same mnemonic, enabling
      reproducibility once the architecture adopts seed-based key recovery.

Why 24 words (256-bit entropy)?
    * BIP-39 only supports five standard sizes: 12 (128-bit), 15 (160-bit),
      18 (192-bit), 21 (224-bit), and 24 (256-bit) words.
    * 24 words / 256-bit entropy is the maximum security level and is what all
      major hardware wallets use by default.
    * 128-bit or 192-bit entropy is sufficient, but 256-bit provides an extra
      margin with negligible cost.

Why the seed is never stored
-----------------------------
Storing the recovery seed would create a second copy of the Vault Key on
disk, negating the purpose of the two-layer key hierarchy.  An attacker who
reads the recovery seed file could reconstruct the Master Key and decrypt
every document in the vault.

The correct model is:

  1. Generate the seed.
  2. Return it to the user *once* in the API response.
  3. Store only a fingerprint (SHA-256 prefix) so that the verify endpoint
     can confirm a candidate seed without requiring the plaintext.
  4. The user writes it down and keeps it in a physically secure location.

Why a fingerprint instead of a hash?
--------------------------------------
A fingerprint (the first 16 hex characters of SHA-256(seed)) is stored so
that:

* The verify endpoint can detect an obviously wrong seed (wrong fingerprint)
  without performing any cryptographic operation.
* It is short enough to log safely (no brute-force risk against a 16-char hex
  fragment of a 256-bit random value).
* It is NOT a password verification record — verification success does not
  grant access to any key material.  Actual account recovery requires the
  full seed AND additional credential confirmation (future milestone).

How this prepares for future vault recovery
--------------------------------------------
When the account recovery milestone is implemented:

1. The user provides the 24-word seed.
2. The seed is validated against the stored fingerprint.
3. A deterministic key derivation (e.g. PBKDF2 or Argon2id with a fixed salt)
   produces a Recovery Master Key from the seed.
4. At vault creation / password change, the Recovery Master Key is used to
   wrap the Vault Key and store it as `recovery_key.json`.
5. If the user forgets their password, they present the seed to unwrap the
   Vault Key from `recovery_key.json` and set a new password.

This module only implements steps 1–3 of this future flow.

Extensibility
-------------
* **Hardware wallets**: the same BIP-39 seed can be imported into a hardware
  wallet (Ledger, Trezor) which then acts as the second factor.
* **Multi-device sync**: share the wrapped Vault Key across devices using the
  Recovery Master Key as the envelope key.
* **Passphrase extension**: BIP-39 optionally supports an additional passphrase
  that is combined with the seed during key derivation (BIP-39 ''25th word'').
  Add a `passphrase: str = ""` parameter to `generate_seed` when needed.
"""

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mnemonic import Mnemonic

from app.core.exceptions import (
    InvalidRecoverySeedError,
    RecoveryMetadataMissingError,
    UnsupportedRecoveryVersionError,
)
from app.core.logger import get_logger

logger = get_logger(__name__)

# BIP-39 entropy bits for a 24-word mnemonic.
_ENTROPY_BITS: int = 256

# Expected word count produced by 256-bit BIP-39 entropy.
SEED_WORD_COUNT: int = 24

# Schema version for recovery_meta.json.
RECOVERY_VERSION: str = "1"

# Algorithm label recorded in metadata so future readers can branch on it.
_RECOVERY_ALGORITHM: str = "BIP39-24-SHA256"

# Checksum schema version (which hash function is used for the fingerprint).
_CHECKSUM_VERSION: str = "sha256-prefix-16"

# Number of hex characters used for the seed fingerprint.
_FINGERPRINT_HEX_LEN: int = 16

_RECOVERY_META_FILENAME: str = "recovery_meta.json"

# Supported recovery versions.  Extend this set when a new version is deployed.
_SUPPORTED_VERSIONS: frozenset[str] = frozenset({"1"})



@dataclass
class RecoveryMetadata:
    """
    In-memory representation of a vault's `recovery_meta.json`.

    This file is written once when a recovery seed is generated.  It
    contains enough information to validate a candidate seed and to
    migrate to a new recovery scheme without re-generating the seed.

    **What is stored:**

    * `recovery_version` — schema version for future migrations.
    * `algorithm` — identifies the seed type and fingerprint hash.
    * `created_at` — UTC ISO-8601 timestamp.
    * `checksum_version` — identifies the fingerprint derivation method.
    * `seed_fingerprint` — first 16 hex characters of SHA-256(seed).

    **What is NOT stored:**

    * Plaintext seed words.
    * Any key material (Master Key, Vault Key, Recovery Master Key).
    * The user's password.

    Attributes
    ----------
    created_at:
        UTC ISO-8601 timestamp of when the recovery seed was generated.
    seed_fingerprint:
        First :data:_FINGERPRINT_HEX_LEN hex characters of SHA-256 of the
        space-joined, lowercase-normalised mnemonic.  Used only to confirm a
        candidate seed without storing the seed itself.
    recovery_version:
        Schema version for `recovery_meta.json`.
    algorithm:
        Label identifying the mnemonic standard and fingerprint hash.
    checksum_version:
        Identifies the fingerprint derivation function.
    """

    created_at: str
    seed_fingerprint: str
    recovery_version: str = field(default=RECOVERY_VERSION)
    algorithm: str = field(default=_RECOVERY_ALGORITHM)
    checksum_version: str = field(default=_CHECKSUM_VERSION)

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dictionary representation."""
        return asdict(self)

    def write(self, path: Path) -> None:
        """
        Serialise this metadata to `path` as pretty-printed JSON.

        Raises
        ------
        OSError
            Propagated from :func:pathlib.Path.write_text on any I/O error.
        """
        path.write_text(json.dumps(self.to_dict(), indent=4), encoding="utf-8")

    @classmethod
    def read(cls, path: Path) -> "RecoveryMetadata":
        """
        Deserialise `recovery_meta.json` into a :class:RecoveryMetadata.

        Unknown fields are silently ignored for forward compatibility.

        Raises
        ------
        FileNotFoundError
            If `path` does not exist.
        json.JSONDecodeError
            If the file is not valid JSON.
        KeyError
            If a required field is missing.
        """
        import dataclasses

        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        known: set[str] = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})



_RECOVERY_KEY_FILENAME: str = "recovery_key.json"


@dataclass
class RecoveryKeyMetadata:
    """
    In-memory representation of `recovery_key.json`.

    Contains the AES-256-GCM ciphertext of the Vault Key wrapped under the
    Recovery Master Key (derived from the BIP-39 seed), along with the nonce
    and salt.
    """

    encrypted_vault_key: str
    nonce: str
    salt: str
    created_at: str
    algorithm: str = field(default=_RECOVERY_ALGORITHM)
    recovery_version: str = field(default=RECOVERY_VERSION)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def write(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=4), encoding="utf-8")

    @classmethod
    def read(cls, path: Path) -> "RecoveryKeyMetadata":
        import dataclasses

        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        known: set[str] = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


class RecoveryManager:
    """
    Manages BIP-39 recovery seed generation, validation, and metadata I/O
    for a single vault.
    """

    def __init__(self, vault_root: Path) -> None:
        self._vault_root: Path = vault_root
        self._meta_path: Path = vault_root / _RECOVERY_META_FILENAME
        self._mnemo: Mnemonic = Mnemonic("english")

    def generate_seed(self, vault_id: str) -> str:
        entropy: bytes = os.urandom(_ENTROPY_BITS // 8)
        seed: str = self._mnemo.to_mnemonic(entropy)

        logger.info(
            "Recovery seed generated | vault_id=%s | words=%d | algorithm=%s",
            vault_id,
            len(seed.split()),
            _RECOVERY_ALGORITHM,
        )

        return seed

    def compute_fingerprint(self, seed: str) -> str:
        normalised: str = " ".join(seed.lower().split())
        return hashlib.sha256(normalised.encode("utf-8")).hexdigest()[
            :_FINGERPRINT_HEX_LEN
        ]

    def validate_seed_format(self, candidate: str) -> None:
        normalised: str = " ".join(candidate.lower().split())
        words = normalised.split()

        if len(words) != SEED_WORD_COUNT:
            raise InvalidRecoverySeedError(
                f"Recovery seed has {len(words)} words; expected {SEED_WORD_COUNT}.",
                detail=(
                    f"A valid recovery seed must contain exactly {SEED_WORD_COUNT} "
                    "words from the BIP-39 English wordlist."
                ),
            )

        if not self._mnemo.check(normalised):
            raise InvalidRecoverySeedError(
                "Recovery seed failed BIP-39 validation.",
                detail=(
                    "The seed words are not a valid BIP-39 mnemonic.  One or more "
                    "words may not be in the BIP-39 English wordlist, or the "
                    "embedded checksum is incorrect."
                ),
            )

    def validate_seed(self, candidate: str, vault_id: str) -> bool:
        self.validate_seed_format(candidate)

        normalised: str = " ".join(candidate.lower().split())

        metadata: RecoveryMetadata = self.read_metadata(vault_id)

        if metadata.recovery_version not in _SUPPORTED_VERSIONS:
            raise UnsupportedRecoveryVersionError(
                f"Unsupported recovery version: '{metadata.recovery_version}'.",
                detail=(
                    f"This Cipherix version supports recovery schema versions: "
                    f"{sorted(_SUPPORTED_VERSIONS)}.  "
                    f"Found '{metadata.recovery_version}' in recovery_meta.json."
                ),
            )

        candidate_fp: str = self.compute_fingerprint(normalised)
        match: bool = candidate_fp == metadata.seed_fingerprint

        logger.info(
            "Recovery seed validation | vault_id=%s | bip39_valid=True | fingerprint_match=%s",
            vault_id,
            match,
        )

        return match

    def write_metadata(self, vault_id: str, seed_fingerprint: str) -> RecoveryMetadata:
        metadata = RecoveryMetadata(
            created_at=datetime.now(UTC).isoformat(),
            seed_fingerprint=seed_fingerprint,
        )

        try:
            metadata.write(self._meta_path)
        except OSError as exc:
            raise OSError(
                f"Failed to write recovery_meta.json for vault '{vault_id}': {exc}"
            ) from exc

        logger.info(
            "Recovery metadata written | vault_id=%s | algorithm=%s | version=%s",
            vault_id,
            _RECOVERY_ALGORITHM,
            RECOVERY_VERSION,
        )

        return metadata

    def read_metadata(self, vault_id: str) -> RecoveryMetadata:
        if not self._meta_path.is_file():
            raise RecoveryMetadataMissingError(
                f"recovery_meta.json not found for vault '{vault_id}'.",
                detail=(
                    f"Vault '{vault_id}' has no recovery seed configured.  "
                    "Call POST /vaults/{vault_id}/recovery-seed first."
                ),
            )

        try:
            metadata = RecoveryMetadata.read(self._meta_path)
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise InvalidRecoverySeedError(
                f"Cannot parse recovery_meta.json for vault '{vault_id}': {exc}",
                detail=(
                    f"The recovery_meta.json for vault '{vault_id}' is malformed "
                    f"or missing required fields: {exc}"
                ),
            ) from exc

        logger.debug(
            "Recovery metadata read | vault_id=%s | version=%s | algorithm=%s",
            vault_id,
            metadata.recovery_version,
            metadata.algorithm,
        )

        return metadata

    def has_recovery_seed(self) -> bool:
        return self._meta_path.is_file()

    def create_recovery_key(
        self,
        vault_id: str,
        vault_key_bytes: bytes,
        seed: str,
    ) -> RecoveryKeyMetadata:
        from app.security.encryption import EncryptionManager
        from app.security.password_manager import PasswordManager

        pwd_mgr = PasswordManager(self._vault_root)
        enc_mgr = EncryptionManager()

        normalised_seed: str = " ".join(seed.lower().split())
        salt_hex: str = pwd_mgr.generate_salt()
        recovery_master_key: bytes = pwd_mgr.derive_master_key(normalised_seed, salt_hex)

        nonce_bytes: bytes = enc_mgr.generate_nonce()
        ciphertext_bytes: bytes = enc_mgr.encrypt_vault_key(
            vault_key=vault_key_bytes,
            master_key=recovery_master_key,
            nonce=nonce_bytes,
        )

        key_meta = RecoveryKeyMetadata(
            encrypted_vault_key=enc_mgr.encode_for_storage(ciphertext_bytes),
            nonce=enc_mgr.encode_for_storage(nonce_bytes),
            salt=salt_hex,
            created_at=datetime.now(UTC).isoformat(),
        )

        key_meta.write(self._vault_root / _RECOVERY_KEY_FILENAME)
        logger.info("recovery_key.json created for vault '%s'", vault_id)
        return key_meta

    def recover_vault_key(self, vault_id: str, seed: str) -> bytes:
        from app.security.encryption import EncryptionManager
        from app.security.password_manager import PasswordManager

        valid: bool = self.validate_seed(seed, vault_id)
        if not valid:
            raise InvalidRecoverySeedError(
                "Recovery seed does not match the vault's stored fingerprint.",
                detail="The candidate seed words failed fingerprint verification for this vault.",
            )

        recovery_key_path = self._vault_root / _RECOVERY_KEY_FILENAME
        if not recovery_key_path.is_file():
            raise RecoveryMetadataMissingError(
                f"recovery_key.json not found for vault '{vault_id}'.",
                detail=f"Vault '{vault_id}' is missing recovery_key.json. Recovery cannot proceed.",
            )

        try:
            key_meta = RecoveryKeyMetadata.read(recovery_key_path)
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise InvalidRecoverySeedError(
                f"Cannot parse recovery_key.json for vault '{vault_id}': {exc}",
                detail=f"The recovery_key.json for vault '{vault_id}' is malformed or unreadable.",
            ) from exc

        pwd_mgr = PasswordManager(self._vault_root)
        enc_mgr = EncryptionManager()

        normalised_seed: str = " ".join(seed.lower().split())
        recovery_master_key: bytes = pwd_mgr.derive_master_key(normalised_seed, key_meta.salt)

        ct_bytes: bytes = enc_mgr.decode_from_storage(
            key_meta.encrypted_vault_key, "encrypted_vault_key"
        )
        nonce_bytes: bytes = enc_mgr.decode_from_storage(key_meta.nonce, "nonce")

        vault_key_bytes: bytes = enc_mgr.decrypt_vault_key(
            ciphertext=ct_bytes,
            master_key=recovery_master_key,
            nonce=nonce_bytes,
        )

        logger.info("Vault Key successfully recovered using recovery seed | vault_id=%s", vault_id)
        return vault_key_bytes

