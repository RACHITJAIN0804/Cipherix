"""
services/blockchain/adapters/local.py
-------------------------------------
Local development implementation of BlockchainAdapter.

DEVELOPMENT IMPLEMENTATION DISCLAIMER:
-------------------------------------
This adapter provides a lightweight, local, deterministic simulation of a
blockchain ledger for offline development and test suites. It DOES NOT provide
the decentralized consensus or immutable public trust guarantees of an external
production blockchain network (e.g. Ethereum / Bitcoin / OpenTimestamps).
"""

import hashlib
import threading
from datetime import UTC, datetime
from typing import Any, Dict, Optional

from app.core.exceptions import BlockchainUnavailableError
from app.core.logger import get_logger
from app.services.blockchain.adapters.base import BlockchainAdapter

logger = get_logger(__name__)


class LocalBlockchainAdapter(BlockchainAdapter):
    """
    Local in-memory simulated blockchain ledger for development & testing.
    """

    def __init__(self, network: str = "local-development") -> None:
        self._network: str = network
        self._ledger: Dict[str, Dict[str, Any]] = {}
        self._block_counter: int = 100
        self._available: bool = True
        self._lock = threading.Lock()

    @property
    def network_name(self) -> str:
        return self._network

    def set_available(self, available: bool) -> None:
        """Helper for unit tests to simulate network outage / recovery."""
        with self._lock:
            self._available = available

    def is_available(self) -> bool:
        with self._lock:
            return self._available

    def anchor_hash(
        self, privacy_reference: str, integrity_hash: str
    ) -> Dict[str, Any]:
        """
        Anchor document integrity hash on local simulated ledger.
        """
        if not self.is_available():
            raise BlockchainUnavailableError(
                "Local development blockchain network is currently unavailable.",
                detail="Simulated local blockchain network is set to offline.",
            )

        with self._lock:
            self._block_counter += 1
            block_number = self._block_counter
            now_iso = datetime.now(UTC).isoformat()

            # Compute deterministic simulated transaction hash
            tx_payload = f"{self._network}:{privacy_reference}:{integrity_hash}:{block_number}:{now_iso}"
            tx_hash = "0x" + hashlib.sha256(tx_payload.encode("utf-8")).hexdigest()

            record = {
                "tx_hash": tx_hash,
                "block_number": block_number,
                "network": self._network,
                "privacy_reference": privacy_reference,
                "integrity_hash": integrity_hash,
                "status": "anchored",
                "anchored_at": now_iso,
            }

            self._ledger[tx_hash] = record
            logger.info(
                "LocalBlockchainAdapter anchored hash | tx_hash=%s | block=%d | ref=%s",
                tx_hash[:16] + "...",
                block_number,
                privacy_reference[:16] + "...",
            )
            return record

    def get_anchor(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve anchor entry from local simulated ledger.
        """
        if not self.is_available():
            raise BlockchainUnavailableError("Local development blockchain network unavailable.")

        with self._lock:
            record = self._ledger.get(tx_hash)
            return dict(record) if record else None

    def verify_anchor(
        self, privacy_reference: str, integrity_hash: str, tx_hash: str
    ) -> bool:
        """
        Verify privacy_reference and integrity_hash against transaction record.
        """
        record = self.get_anchor(tx_hash)
        if record is None:
            return False
        return (
            record.get("privacy_reference") == privacy_reference
            and record.get("integrity_hash") == integrity_hash
        )
