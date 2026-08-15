"""
services/blockchain/adapters/base.py
------------------------------------
Abstract Base Class defining the BlockchainAdapter interface.

Decouples Cipherix application logic from specific blockchain network drivers
(Local development, Ethereum, Hyperledger, etc.).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BlockchainAdapter(ABC):
    """
    Abstract interface for blockchain anchor providers.
    """

    @property
    @abstractmethod
    def network_name(self) -> str:
        """Return human-readable network identifier (e.g. 'local-development')."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the blockchain provider network is online and accepting transactions."""
        pass

    @abstractmethod
    def anchor_hash(
        self, privacy_reference: str, integrity_hash: str
    ) -> Dict[str, Any]:
        """
        Anchor a cryptographic document hash on the blockchain.

        Parameters
        ----------
        privacy_reference:
            Hashed/salted privacy-preserving reference identifier.
        integrity_hash:
            64-character hex SHA-256 integrity hash of document ciphertext.

        Returns
        -------
        dict
            Transaction receipt containing:
            tx_hash, block_number, network, status, anchored_at.
        """
        pass

    @abstractmethod
    def get_anchor(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve an anchor record from the blockchain by transaction hash.
        """
        pass

    @abstractmethod
    def verify_anchor(
        self, privacy_reference: str, integrity_hash: str, tx_hash: str
    ) -> bool:
        """
        Verify if a privacy_reference and integrity_hash match the ledger record at tx_hash.
        """
        pass
