from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class BlockchainConfig:
    rpc_url: str
    chain_id: int
    deployer_address: str
    private_key: str
    contract_address: str
    gas_limit: int
    connection_timeout_seconds: int
    network: str
    provider: str
    enabled: bool

    @property
    def has_private_key(self) -> bool:
        return bool(self.private_key)

    @property
    def has_contract(self) -> bool:
        return bool(self.contract_address)

    @property
    def is_ganache(self) -> bool:
        return self.provider == "ganache"

    @property
    def private_key_bytes(self) -> bytes:
        key = self.private_key
        if key.startswith("0x") or key.startswith("0X"):
            key = key[2:]
        return bytes.fromhex(key)

    def log_summary(self) -> None:
        logger.info(
            "BlockchainConfig | provider=%s | network=%s | rpc=%s | chain_id=%d "
            "| has_key=%s | has_contract=%s | enabled=%s",
            self.provider,
            self.network,
            self.rpc_url,
            self.chain_id,
            self.has_private_key,
            self.has_contract,
            self.enabled,
        )


@lru_cache(maxsize=1)
def get_blockchain_config() -> BlockchainConfig:
    cfg = BlockchainConfig(
        rpc_url=settings.blockchain_rpc_url,
        chain_id=settings.blockchain_chain_id,
        deployer_address=settings.blockchain_deployer_address,
        private_key=settings.blockchain_private_key,
        contract_address=settings.blockchain_contract_address,
        gas_limit=settings.blockchain_gas_limit,
        connection_timeout_seconds=settings.blockchain_connection_timeout_seconds,
        network=settings.blockchain_network,
        provider=settings.blockchain_provider,
        enabled=settings.blockchain_enabled,
    )
    cfg.log_summary()
    return cfg
