from __future__ import annotations

from typing import Optional

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

from app.core.logger import get_logger
from app.services.blockchain.config import BlockchainConfig, get_blockchain_config

logger = get_logger(__name__)


class GanacheConnectionError(Exception):
    pass


class GanacheClient:

    def __init__(self, config: Optional[BlockchainConfig] = None) -> None:
        self._config = config or get_blockchain_config()
        self._w3: Optional[Web3] = None

    @property
    def config(self) -> BlockchainConfig:
        return self._config

    def connect(self) -> Web3:
        if self._w3 is not None and self._w3.is_connected():
            return self._w3

        logger.info(
            "Connecting to Ganache | rpc=%s | chain_id=%d",
            self._config.rpc_url,
            self._config.chain_id,
        )

        provider = Web3.HTTPProvider(
            self._config.rpc_url,
            request_kwargs={"timeout": self._config.connection_timeout_seconds},
        )
        w3 = Web3(provider)

        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        if not w3.is_connected():
            raise GanacheConnectionError(
                f"Cannot connect to Ganache RPC at '{self._config.rpc_url}'. "
                "Make sure Ganache is running: npx ganache --deterministic"
            )

        node_chain_id = w3.eth.chain_id
        if node_chain_id != self._config.chain_id:
            raise GanacheConnectionError(
                f"Chain ID mismatch: config expects {self._config.chain_id}, "
                f"but connected node reports {node_chain_id}. "
                "Update BLOCKCHAIN_CHAIN_ID in your .env to match."
            )

        logger.info(
            "Connected to Ganache | chain_id=%d | latest_block=%d | accounts=%d",
            node_chain_id,
            w3.eth.block_number,
            len(w3.eth.accounts),
        )

        self._w3 = w3
        return self._w3

    @property
    def w3(self) -> Web3:
        if self._w3 is None or not self._w3.is_connected():
            return self.connect()
        return self._w3

    def is_connected(self) -> bool:
        try:
            if self._w3 is None:
                return False
            return self._w3.is_connected()
        except Exception:
            return False

    def get_balance(self, address: str) -> int:
        return self.w3.eth.get_balance(Web3.to_checksum_address(address))

    def get_block_number(self) -> int:
        return self.w3.eth.block_number

    def get_accounts(self) -> list[str]:
        return list(self.w3.eth.accounts)

    def health(self) -> dict:
        try:
            w3 = self.connect()
            return {
                "connected": True,
                "chain_id": w3.eth.chain_id,
                "block_number": w3.eth.block_number,
                "rpc_url": self._config.rpc_url,
                "network": self._config.network,
                "accounts": len(w3.eth.accounts),
            }
        except GanacheConnectionError as exc:
            return {
                "connected": False,
                "rpc_url": self._config.rpc_url,
                "error": str(exc),
            }
        except Exception as exc:
            logger.error("Unexpected error in GanacheClient.health(): %s", exc)
            return {
                "connected": False,
                "rpc_url": self._config.rpc_url,
                "error": f"Unexpected error: {type(exc).__name__}: {exc}",
            }

    def disconnect(self) -> None:
        self._w3 = None
        logger.debug("GanacheClient disconnected.")
