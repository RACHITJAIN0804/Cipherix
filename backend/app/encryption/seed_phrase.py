"""
app/encryption/seed_phrase.py
------------------------------
Utility wrapper around Cipherix 16-word BIP-39 recovery seed phrase functionality.
Reuses the authoritative implementation in app.security.recovery.
"""

from pathlib import Path
from typing import Any

from app.security.recovery import (
    SEED_WORD_COUNT,
    RecoveryManager,
)


class SeedPhraseManager:
    """Convenience wrapper around RecoveryManager for seed phrase operations."""

    def __init__(self, vault_root: Path | None = None) -> None:
        self._recovery_mgr = RecoveryManager(vault_root or Path("."))

    def generate_seed(self, vault_id: str = "default") -> str:
        """Generate a valid 16-word BIP-39 seed phrase."""
        return self._recovery_mgr.generate_seed(vault_id)

    def validate_seed(self, candidate: str) -> None:
        """Validate candidate 16-word BIP-39 seed phrase format and checksum."""
        self._recovery_mgr.validate_seed_format(candidate)

    def compute_fingerprint(self, seed: str) -> str:
        """Compute the deterministic 16-character SHA-256 fingerprint for a seed."""
        return self._recovery_mgr.compute_fingerprint(seed)
