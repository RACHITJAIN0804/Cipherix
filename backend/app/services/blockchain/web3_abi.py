"""
web3_abi.py — Web3.py helper for the DocumentIntegrity smart contract.

Provides:
  - ABI loading from the build artifact
  - A ready-to-use DocumentIntegrityContract wrapper class

Usage:
    from app.services.blockchain.web3_abi import load_abi, DocumentIntegrityContract

The ABI is loaded from:
    app/services/blockchain/contracts/build/DocumentIntegrity.abi.json

This file is the canonical Web3.py ABI source for Cipherix.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional

from web3 import Web3
from web3.contract import Contract

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_BUILD_DIR = Path(__file__).parent / "contracts" / "build"
_ABI_PATH = _BUILD_DIR / "DocumentIntegrity.abi.json"
_DEPLOYMENT_PATH = _BUILD_DIR / "deployment.json"


# ---------------------------------------------------------------------------
# ABI loader
# ---------------------------------------------------------------------------

def load_abi() -> list:
    """Load the DocumentIntegrity ABI from the compiled build artifact.

    Returns:
        The ABI as a Python list, suitable for passing to ``w3.eth.contract(abi=...)``.

    Raises:
        FileNotFoundError: If the contract has not been compiled yet.
    """
    if not _ABI_PATH.exists():
        raise FileNotFoundError(
            f"ABI not found at {_ABI_PATH}.\n"
            "Run 'python -m app.services.blockchain.compile' from the backend/ directory first."
        )
    return json.loads(_ABI_PATH.read_text(encoding="utf-8"))


def load_deployment() -> dict:
    """Load the most recent deployment record.

    Returns:
        dict with contractAddress, chainId, deployedAt, abi, etc.

    Raises:
        FileNotFoundError: If the contract has not been deployed yet.
    """
    if not _DEPLOYMENT_PATH.exists():
        raise FileNotFoundError(
            f"Deployment record not found at {_DEPLOYMENT_PATH}.\n"
            "Run 'python -m app.services.blockchain.deploy' from the backend/ directory first."
        )
    return json.loads(_DEPLOYMENT_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def str_to_bytes32(value: str) -> bytes:
    """SHA-256 hash a string to a bytes32 value for on-chain use.

    Args:
        value: A string (e.g. document UUID or vault ID string).

    Returns:
        32-byte ``bytes`` object.
    """
    return hashlib.sha256(value.encode("utf-8")).digest()


def hex_to_bytes32(hex_str: str) -> bytes:
    """Convert a hex string (with or without '0x' prefix) to bytes32.

    Args:
        hex_str: Hexadecimal string representing a SHA-256 digest.

    Returns:
        32-byte ``bytes`` object.
    """
    clean = hex_str.removeprefix("0x").removeprefix("0X")
    raw = bytes.fromhex(clean)
    if len(raw) != 32:
        raise ValueError(f"Expected 32 bytes, got {len(raw)} from '{hex_str}'")
    return raw


def bytes32_to_hex(value: bytes) -> str:
    """Convert a bytes32 value to a '0x'-prefixed hex string.

    Args:
        value: 32-byte ``bytes`` object.

    Returns:
        Lowercase hex string with '0x' prefix.
    """
    return "0x" + value.hex()


# ---------------------------------------------------------------------------
# Contract wrapper
# ---------------------------------------------------------------------------

class DocumentIntegrityContract:
    """High-level wrapper around the ``DocumentIntegrity`` Solidity contract.

    Provides typed Python methods for every public contract function.
    Transactions are signed locally using the deployer's private key.

    Example::

        from app.services.blockchain.web3_abi import DocumentIntegrityContract

        c = DocumentIntegrityContract.from_deployment()
        tx_hash = c.record_hash("doc-uuid-123", "vault-abc", "0x" + sha256_hex)
        result   = c.get_record("doc-uuid-123")
        matched, exists = c.verify_hash("doc-uuid-123", "0x" + sha256_hex)
    """

    def __init__(
        self,
        w3: Web3,
        contract: Contract,
        private_key: str,
        deployer_address: str,
    ) -> None:
        self._w3 = w3
        self._contract = contract
        self._private_key = private_key
        self._deployer_address = Web3.to_checksum_address(deployer_address)

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_deployment(
        cls,
        rpc_url: str = "http://127.0.0.1:8545",
        private_key: Optional[str] = None,
        deployer_address: Optional[str] = None,
        contract_address: Optional[str] = None,
    ) -> "DocumentIntegrityContract":
        """Create a wrapper by reading the saved deployment record.

        Args:
            rpc_url: Ganache RPC endpoint.
            private_key: Override the deployer private key (reads from .env otherwise).
            deployer_address: Override the deployer address.
            contract_address: Override the contract address (uses deployment.json otherwise).

        Returns:
            Connected ``DocumentIntegrityContract`` instance.
        """
        deployment = load_deployment()
        abi = deployment["abi"]

        resolved_address = contract_address or deployment["contractAddress"]
        resolved_deployer = deployer_address or deployment["deployerAddress"]

        if private_key is None:
            # Fall back to settings
            from app.services.blockchain.config import get_blockchain_config
            cfg = get_blockchain_config()
            private_key = cfg.private_key

        from web3.middleware import ExtraDataToPOAMiddleware
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        contract = w3.eth.contract(
            address=Web3.to_checksum_address(resolved_address),
            abi=abi,
        )
        return cls(w3, contract, private_key, resolved_deployer)

    @classmethod
    def from_abi(
        cls,
        w3: Web3,
        contract_address: str,
        private_key: str,
        deployer_address: str,
    ) -> "DocumentIntegrityContract":
        """Create a wrapper using a pre-connected Web3 instance and an explicit address.

        Args:
            w3: Connected ``Web3`` instance.
            contract_address: Deployed contract address.
            private_key: Deployer private key for signing transactions.
            deployer_address: Deployer wallet address.

        Returns:
            ``DocumentIntegrityContract`` instance.
        """
        abi = load_abi()
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=abi,
        )
        return cls(w3, contract, private_key, deployer_address)

    # ------------------------------------------------------------------
    # Internal transaction helper
    # ------------------------------------------------------------------

    def _send_tx(self, fn) -> str:  # type: ignore[type-arg]
        """Build, sign, and broadcast a transaction. Returns the tx hash."""
        nonce = self._w3.eth.get_transaction_count(self._deployer_address)
        gas_estimate = fn.estimate_gas({"from": self._deployer_address})
        tx = fn.build_transaction({
            "from": self._deployer_address,
            "nonce": nonce,
            "gas": int(gas_estimate * 1.2),
            "gasPrice": self._w3.eth.gas_price,
            "chainId": self._w3.eth.chain_id,
        })
        pk = self._private_key
        if not pk.startswith(("0x", "0X")):
            pk = "0x" + pk
        signed = self._w3.eth.account.sign_transaction(tx, private_key=pk)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        return "0x" + tx_hash.hex()

    # ------------------------------------------------------------------
    # Write functions (require gas / signing)
    # ------------------------------------------------------------------

    def record_hash(
        self,
        document_id: str,
        vault_id: str,
        document_hash_hex: str,
    ) -> str:
        """Record a document's integrity hash on-chain.

        Args:
            document_id: Document UUID string (will be SHA-256 hashed to bytes32).
            vault_id: Vault string ID (will be SHA-256 hashed to bytes32).
            document_hash_hex: SHA-256 hex digest of the encrypted ciphertext
                               (with or without '0x' prefix).

        Returns:
            Transaction hash as a hex string.

        Raises:
            ContractLogicError: If the record already exists (DocumentAlreadyExists).
            ContractLogicError: If the hash is zero (InvalidHash).
        """
        doc_id_b32 = str_to_bytes32(document_id)
        vault_id_b32 = str_to_bytes32(vault_id)
        doc_hash_b32 = hex_to_bytes32(document_hash_hex)
        fn = self._contract.functions.recordHash(doc_id_b32, vault_id_b32, doc_hash_b32)
        return self._send_tx(fn)

    # ------------------------------------------------------------------
    # Read functions (no gas, no signing)
    # ------------------------------------------------------------------

    def get_record(self, document_id: str) -> dict:
        """Retrieve the full record for a document.

        Args:
            document_id: Document UUID string.

        Returns:
            dict with keys: vaultId, documentHash, timestamp, recorder
                            (vaultId and documentHash are '0x'-prefixed hex strings).

        Raises:
            ContractLogicError: If the document does not exist (DocumentNotFound).
        """
        doc_id_b32 = str_to_bytes32(document_id)
        vault_id_b, doc_hash_b, timestamp, recorder = (
            self._contract.functions.getRecord(doc_id_b32).call()
        )
        return {
            "vaultId": bytes32_to_hex(vault_id_b),
            "documentHash": bytes32_to_hex(doc_hash_b),
            "timestamp": timestamp,
            "recorder": recorder,
        }

    def verify_hash(self, document_id: str, document_hash_hex: str) -> dict:
        """Verify that a supplied hash matches the on-chain record.

        Args:
            document_id: Document UUID string.
            document_hash_hex: SHA-256 hex digest to check.

        Returns:
            dict with keys: matched (bool), exists (bool).
        """
        doc_id_b32 = str_to_bytes32(document_id)
        doc_hash_b32 = hex_to_bytes32(document_hash_hex)
        matched, exists = self._contract.functions.verifyHash(doc_id_b32, doc_hash_b32).call()
        return {"matched": matched, "exists": exists}

    def record_exists(self, document_id: str) -> bool:
        """Check whether a record exists for the given document ID.

        Args:
            document_id: Document UUID string.

        Returns:
            True if a record exists, False otherwise.
        """
        doc_id_b32 = str_to_bytes32(document_id)
        return self._contract.functions.recordExists(doc_id_b32).call()

    def get_owner(self) -> str:
        """Return the contract owner address."""
        return self._contract.functions.owner().call()

    def is_authorized(self, address: str) -> bool:
        """Check whether an address is authorized to record hashes.

        Args:
            address: Ethereum address string.

        Returns:
            True if authorized.
        """
        return self._contract.functions.authorized(
            Web3.to_checksum_address(address)
        ).call()
