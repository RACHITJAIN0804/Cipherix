
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BlockchainAdapter(ABC):

    @property
    @abstractmethod
    def network_name(self) -> str:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def anchor_hash(
        self, privacy_reference: str, integrity_hash: str
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_anchor(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def verify_anchor(
        self, privacy_reference: str, integrity_hash: str, tx_hash: str
    ) -> bool:
        pass
