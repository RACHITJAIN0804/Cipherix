"""
ganache.py — GanacheAdapter: BlockchainAdapter implementation backed by the
             deployed DocumentIntegrity Solidity contract via Web3.py.

This adapter is selected when BLOCKCHAIN_PROVIDER=ganache in .env.
It bridges the BlockchainService's (privacy_reference, integrity_hash) interface
to the contract's (documentId, vaultId, documentHash) on-chain API.

Encoding strategy
-----------------
  documentId  (bytes32)  = SHA-256( privacy_reference )
                           privacy_reference is already an HMAC-SHA256 hex string;
                           we SHA-256 it again so the on-chain key is always a
                           uniform bytes32 regardless of the caller's format.

  vaultId     (bytes32)  = SHA-256( network_label )
                           stable per deployment; anchors can be scoped to the
                           network string ("local-development") without exposing
                           the real vault UUID.

  documentHash (bytes32) = bytes.fromhex( integrity_hash )
                           integrity_hash is the 64-char hex SHA-256 digest of
                           the encrypted ciphertext blob; we decode it directly
                           to 32 bytes for the contract.

Security notes
--------------
  - Private keys are never logged at any level.
  - Transaction hashes are truncated to 16 chars in INFO-level messages.
  - integrity_hash values are not logged; only their existence is noted.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from web3 import Web3
from web3.exceptions import ContractLogicError
from web3.middleware import ExtraDataToPOAMiddleware

from app.core.exceptions import (
    AnchorAlreadyExistsError,
    AnchorNotFoundError,
    BlockchainError,
    BlockchainUnavailableError,
    ConfigurationError,
)
from app.core.logger import get_logger
from app.services.blockchain.adapters.base import BlockchainAdapter

logger = get_logger(__name__)


def _str_to_bytes32(value: str) -> bytes:
    """SHA-256 hash a string to a 32-byte value for on-chain use."""
    return hashlib.sha256(value.encode("utf-8")).digest()


def _hex_to_bytes32(hex_str: str) -> bytes:
    """Decode a 64-char hex string (SHA-256 digest) to 32 bytes."""
    clean = hex_str.removeprefix("0x").removeprefix("0X")
    raw = bytes.fromhex(clean)
    if len(raw) != 32:
        raise BlockchainError(
            f"Expected a 32-byte (64 hex char) hash; got {len(raw)} bytes from '{hex_str[:12]}...'"
        )
    return raw


def _bytes32_to_hex(value: bytes) -> str:
    """Convert 32 bytes to a lowercase '0x'-prefixed hex string."""
    return "0x" + value.hex()


class GanacheAdapter(BlockchainAdapter):
    """BlockchainAdapter that writes to the live DocumentIntegrity contract.

    Args:
        rpc_url: Ganache JSON-RPC endpoint (default: http://127.0.0.1:8545).
        chain_id: Expected EVM chain ID (default: 1337).
        contract_address: Deployed contract address.
        private_key: Deployer private key for signing transactions.
        deployer_address: Deployer wallet address.
        network: Network label string stored in anchor records.
        connection_timeout: Seconds to wait for RPC connection.
    """

    def __init__(
        self,
        rpc_url: str,
        chain_id: int,
        contract_address: str,
        private_key: str,
        deployer_address: str,
        network: str = "local-development",
        connection_timeout: int = 10,
    ) -> None:
        self._rpc_url = rpc_url
        self._chain_id = chain_id
        self._contract_address = contract_address
        self._private_key = private_key
        self._deployer_address = deployer_address
        self._network = network
        self._connection_timeout = connection_timeout

        # Lazy-initialised — created on first use
        self._contract: Optional[Any] = None
        self._w3: Optional[Web3] = None

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_settings(cls) -> "GanacheAdapter":
        """Construct a GanacheAdapter from the Cipherix application settings."""
        from app.services.blockchain.config import get_blockchain_config

        cfg = get_blockchain_config()

        if not cfg.has_private_key:
            raise ConfigurationError(
                "BLOCKCHAIN_PRIVATE_KEY is not configured. "
                "Set it to the Ganache deployer private key in .env."
            )
        if not cfg.has_contract:
            raise ConfigurationError(
                "BLOCKCHAIN_CONTRACT_ADDRESS is not configured. "
                "Run 'python -m app.services.blockchain.deploy' and set the address in .env."
            )

        return cls(
            rpc_url=cfg.rpc_url,
            chain_id=cfg.chain_id,
            contract_address=cfg.contract_address,
            private_key=cfg.private_key,
            deployer_address=cfg.deployer_address,
            network=cfg.network,
            connection_timeout=cfg.connection_timeout_seconds,
        )

    # ------------------------------------------------------------------
    # Internal: lazy Web3 + contract setup
    # ------------------------------------------------------------------

    def _get_contract(self) -> Any:
        """Return the bound contract instance, creating it on first call."""
        if self._contract is not None:
            return self._contract

        from app.services.blockchain.web3_abi import load_abi

        try:
            abi = load_abi()
        except FileNotFoundError as exc:
            raise ConfigurationError(str(exc)) from exc

        try:
            w3 = Web3(
                Web3.HTTPProvider(
                    self._rpc_url,
                    request_kwargs={"timeout": self._connection_timeout},
                )
            )
            w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

            if not w3.is_connected():
                raise BlockchainUnavailableError(
                    f"Cannot connect to Ganache RPC at '{self._rpc_url}'. "
                    "Make sure Ganache is running: npx ganache --deterministic"
                )

            node_chain_id = w3.eth.chain_id
            if node_chain_id != self._chain_id:
                raise BlockchainUnavailableError(
                    f"Chain ID mismatch: expected {self._chain_id}, "
                    f"connected node reports {node_chain_id}. "
                    "Update BLOCKCHAIN_CHAIN_ID in .env."
                )

        except BlockchainUnavailableError:
            raise
        except Exception as exc:
            raise BlockchainUnavailableError(
                f"Unexpected error connecting to Ganache: {type(exc).__name__}: {exc}"
            ) from exc

        contract = w3.eth.contract(
            address=Web3.to_checksum_address(self._contract_address),
            abi=abi,
        )

        self._w3 = w3
        self._contract = contract
        logger.info(
            "GanacheAdapter connected | rpc=%s | chain_id=%d | contract=%s",
            self._rpc_url,
            node_chain_id,
            self._contract_address[:10] + "...",
        )
        return self._contract

    def _send_tx(self, fn: Any) -> Dict[str, Any]:
        """Build, sign, broadcast a transaction and wait for the receipt."""
        w3 = self._w3
        assert w3 is not None  # ensured by _get_contract()

        deployer = Web3.to_checksum_address(self._deployer_address)

        try:
            nonce = w3.eth.get_transaction_count(deployer)
            # estimate_gas raises ContractLogicError / Exception for custom reverts
            gas_estimate = fn.estimate_gas({"from": deployer})
            gas_limit = int(gas_estimate * 1.2)

            tx = fn.build_transaction({
                "from": deployer,
                "nonce": nonce,
                "gas": gas_limit,
                "gasPrice": w3.eth.gas_price,
                "chainId": w3.eth.chain_id,
            })

            pk = self._private_key
            if not pk.startswith(("0x", "0X")):
                pk = "0x" + pk

            signed = w3.eth.account.sign_transaction(tx, private_key=pk)
            tx_hash_bytes = w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash_bytes, timeout=120)

            if receipt.status != 1:
                # Re-raise as a revert so the except block handles it uniformly
                raise ContractLogicError(
                    "execution reverted",
                    data={"result": "0x"},
                )

            return {
                "tx_hash": "0x" + tx_hash_bytes.hex(),
                "block_number": receipt.blockNumber,
                "gas_used": receipt.gasUsed,
            }

        except BlockchainError:
            raise
        except (ContractLogicError, Exception) as exc:
            self._raise_contract_error(exc)
            raise  # unreachable; satisfies type checkers

    def _raise_contract_error(self, exc: Exception) -> None:
        """Inspect a revert exception and re-raise the correct Cipherix error.

        Ganache returns raw revert bytes rather than decoded custom-error names.
        We match the 4-byte selector prefix of the ABI-encoded custom error.

        Custom error selectors (keccak256 of signature, first 4 bytes):
          DocumentAlreadyExists(bytes32)  ->  0x4cba5033
          DocumentNotFound(bytes32)       ->  0x6c77a3c3  (for reference)
          NotAuthorized()                 ->  0x82b42900
          InvalidHash()                   ->  0x53d5e822
          InvalidAddress()                ->  0xe6c4247b
        """
        raw = self._extract_revert_bytes(exc)

        # Match by 4-byte selector prefix
        if raw and raw[:4].hex() == "4cba5033":
            raise AnchorAlreadyExistsError(
                "A blockchain record for this document already exists."
            ) from exc

        # Check string-based match as fallback (decoded environments)
        reason = str(exc)
        if "DocumentAlreadyExists" in reason:
            raise AnchorAlreadyExistsError(
                "A blockchain record for this document already exists."
            ) from exc

        if "NotAuthorized" in reason or (raw and raw[:4].hex() == "82b42900"):
            from app.core.exceptions import BlockchainVerificationError
            raise BlockchainVerificationError(
                "Caller is not authorized to record hashes."
            ) from exc

        raise BlockchainError(f"Contract reverted: {exc}") from exc

    @staticmethod
    def _extract_revert_bytes(exc: Exception) -> Optional[bytes]:
        """Extract raw revert data bytes from a revert exception if available."""
        # ContractLogicError may carry a 'data' dict with 'result' hex
        if isinstance(exc, ContractLogicError):
            try:
                args = exc.args
                # args[1] is often a dict like {'result': '0x4cba5033...'}
                for arg in args:
                    if isinstance(arg, dict):
                        result_hex = arg.get("result", "")
                        if result_hex and result_hex not in ("0x", ""):
                            raw = bytes.fromhex(result_hex.removeprefix("0x"))
                            if len(raw) >= 4:
                                return raw
            except Exception:
                pass

        # Also check the plain string for a hex payload
        raw_str = str(exc)
        # Look for '0x' followed by 8+ hex chars in the message
        import re
        match = re.search(r"'result':\s*'(0x[0-9a-fA-F]{8,})'", raw_str)
        if match:
            try:
                return bytes.fromhex(match.group(1).removeprefix("0x"))
            except Exception:
                pass

        return None


    # ------------------------------------------------------------------
    # BlockchainAdapter protocol
    # ------------------------------------------------------------------

    @property
    def network_name(self) -> str:
        return self._network

    def is_available(self) -> bool:
        """Return True if Ganache is reachable and the contract is callable."""
        try:
            contract = self._get_contract()
            contract.functions.owner().call()
            return True
        except Exception:
            return False

    def anchor_hash(
        self, privacy_reference: str, integrity_hash: str
    ) -> Dict[str, Any]:
        """Record (documentId, vaultId, documentHash) on-chain.

        Args:
            privacy_reference: HMAC-SHA256 hex string used as the document key.
            integrity_hash: SHA-256 hex digest of the encrypted ciphertext blob.

        Returns:
            dict with tx_hash, block_number, gas_used, network, status.

        Raises:
            BlockchainUnavailableError: Ganache unreachable.
            AnchorAlreadyExistsError: Record already on-chain for this document.
            BlockchainError: Any other on-chain failure.
        """
        contract = self._get_contract()

        document_id_b32 = _str_to_bytes32(privacy_reference)
        vault_id_b32 = _str_to_bytes32(self._network)
        try:
            doc_hash_b32 = _hex_to_bytes32(integrity_hash)
        except (ValueError, BlockchainError) as exc:
            raise BlockchainError(f"Invalid integrity_hash format: {exc}") from exc

        fn = contract.functions.recordHash(document_id_b32, vault_id_b32, doc_hash_b32)
        receipt = self._send_tx(fn)

        logger.info(
            "GanacheAdapter anchor_hash | tx=%s | block=%d | gas=%d",
            receipt["tx_hash"][:18] + "...",
            receipt["block_number"],
            receipt["gas_used"],
        )

        return {
            "tx_hash": receipt["tx_hash"],
            "block_number": receipt["block_number"],
            "gas_used": receipt["gas_used"],
            "network": self._network,
            "status": "anchored",
        }

    def get_anchor(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve an anchor record keyed by the privacy_reference stored as tx_hash.

        In the Ganache adapter, ``tx_hash`` is the actual Ethereum tx hash produced
        by ``anchor_hash``. However, the contract is keyed by ``documentId`` (bytes32),
        not by tx hash. This method therefore cannot look up a record solely by tx hash
        without the original ``privacy_reference``.

        Returns ``None`` when lookup is not possible via tx hash alone.
        Callers that need the full record should use ``get_anchor_by_reference``.
        """
        # The contract is keyed by documentId (bytes32), not tx hash.
        # Without the original privacy_reference we cannot reconstruct documentId.
        # Return None to signal "not retrievable via tx_hash" — the service layer
        # treats None as "blockchain unavailable for cross-check", which is correct.
        logger.debug(
            "GanacheAdapter.get_anchor: lookup-by-tx-hash not supported; "
            "use get_anchor_by_reference instead."
        )
        return None

    def get_anchor_by_reference(self, privacy_reference: str) -> Optional[Dict[str, Any]]:
        """Retrieve an on-chain record using the original privacy_reference.

        Args:
            privacy_reference: The HMAC-SHA256 hex string used when anchoring.

        Returns:
            dict with vaultId, documentHash, timestamp, recorder — or None if not found.
        """
        contract = self._get_contract()
        document_id_b32 = _str_to_bytes32(privacy_reference)

        try:
            exists = contract.functions.recordExists(document_id_b32).call()
            if not exists:
                return None

            vault_id_b, doc_hash_b, timestamp, recorder = (
                contract.functions.getRecord(document_id_b32).call()
            )
            return {
                "vault_id": _bytes32_to_hex(vault_id_b),
                "integrity_hash": _bytes32_to_hex(doc_hash_b),
                "timestamp": timestamp,
                "recorder": recorder,
                "network": self._network,
            }

        except ContractLogicError as exc:
            raise BlockchainError(f"Contract error during getRecord: {exc}") from exc
        except Exception as exc:
            raise BlockchainUnavailableError(
                f"RPC error during getRecord: {type(exc).__name__}: {exc}"
            ) from exc

    def verify_anchor(
        self, privacy_reference: str, integrity_hash: str, tx_hash: str  # noqa: ARG002
    ) -> bool:
        """Verify that the on-chain hash matches the supplied integrity_hash.

        Args:
            privacy_reference: HMAC-SHA256 string used as the document key.
            integrity_hash: SHA-256 hex digest to compare against the on-chain record.
            tx_hash: Unused for Ganache (contract is keyed by documentId, not tx hash).

        Returns:
            True if the hashes match, False otherwise.
        """
        contract = self._get_contract()
        document_id_b32 = _str_to_bytes32(privacy_reference)

        try:
            doc_hash_b32 = _hex_to_bytes32(integrity_hash)
        except (ValueError, BlockchainError):
            return False

        try:
            matched, exists = contract.functions.verifyHash(
                document_id_b32, doc_hash_b32
            ).call()
            logger.info(
                "GanacheAdapter verify_anchor | exists=%s | matched=%s",
                exists,
                matched,
            )
            return bool(matched and exists)

        except ContractLogicError as exc:
            raise BlockchainError(f"Contract error during verifyHash: {exc}") from exc
        except Exception as exc:
            raise BlockchainUnavailableError(
                f"RPC error during verifyHash: {type(exc).__name__}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Health / status
    # ------------------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        """Return a health-check dict for the Ganache connection.

        Returns:
            dict with: connected, rpc_url, chain_id, block_number,
                       contract_address, network, provider, deployer_address.
        """
        base = {
            "provider": "ganache",
            "network": self._network,
            "rpc_url": self._rpc_url,
            "chain_id": self._chain_id,
            "contract_address": self._contract_address,
            "deployer_address": self._deployer_address,
            "connected": False,
            "block_number": None,
            "error": None,
        }

        try:
            contract = self._get_contract()
            w3 = self._w3
            assert w3 is not None

            block_number = w3.eth.block_number
            owner = contract.functions.owner().call()

            base.update({
                "connected": True,
                "block_number": block_number,
                "contract_owner": owner,
                "error": None,
            })
        except Exception as exc:
            base["error"] = f"{type(exc).__name__}: {exc}"
            logger.warning("GanacheAdapter health check failed: %s", exc)

        return base
