
from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class AnchorRequest(BaseModel):

    vault_id: str = Field(..., description="UUID of the vault containing the document.")
    document_id: str = Field(..., description="UUID of the document to anchor.")


class AnchorResponse(BaseModel):

    model_config = ConfigDict(from_attributes=True)

    anchor_id: str = Field(..., description="UUID of the internal anchor record.")
    document_id: str = Field(..., description="UUID of the anchored document.")
    vault_id: Optional[str] = Field(default=None, description="UUID of the vault (nullable for legacy records).")
    privacy_reference: str = Field(..., description="Privacy-preserving reference hash.")
    integrity_hash: str = Field(..., description="Anchored SHA-256 integrity hash.")
    network: str = Field(..., description="Blockchain network name.")
    tx_hash: str = Field(..., description="Blockchain transaction hash / block reference.")
    block_number: int = Field(..., description="Block number on the ledger.")
    status: str = Field(..., description="Anchor status ('anchored', 'pending', 'failed').")
    anchored_at: datetime = Field(..., description="UTC timestamp when anchor was confirmed.")
    last_verified_at: Optional[datetime] = Field(default=None, description="UTC timestamp of the most recent verification call.")
    last_verification_result: Optional[bool] = Field(default=None, description="Result of the most recent verification: True=matched, False=mismatch, None=never verified.")
    error_message: Optional[str] = Field(default=None, description="Error message from the last failed blockchain operation, if any.")


class VerifyAnchorRequest(BaseModel):

    vault_id: str = Field(..., description="UUID of the vault containing the document.")
    document_id: str = Field(..., description="UUID of the document to verify.")


class VerifyAnchorResponse(BaseModel):

    document_id: str = Field(..., description="UUID of verified document.")
    privacy_reference: str = Field(..., description="Privacy-preserving document reference.")
    stored_integrity_hash: str = Field(..., description="SHA-256 hash stored in DB metadata.")
    current_integrity_hash: str = Field(..., description="SHA-256 hash recalculated from disk ciphertext.")
    current_hash: Optional[str] = Field(default=None, description="Recalculated SHA-256 hash from disk ciphertext.")
    blockchain_hash: Optional[str] = Field(default=None, description="Hash retrieved from blockchain record.")
    integrity_match: bool = Field(..., description="Whether disk ciphertext hash matches stored DB hash.")
    blockchain_match: bool = Field(..., description="Whether disk ciphertext hash matches blockchain anchor.")
    verified: bool = Field(..., description="Overall verification result (true if both matches pass).")
    network: str = Field(..., description="Blockchain network label.")
    tx_hash: Optional[str] = Field(default=None, description="Blockchain transaction hash.")
    anchored_at: Optional[datetime] = Field(default=None, description="Timestamp of blockchain anchor.")
    verified_at: Optional[datetime] = Field(default=None, description="Timestamp when verification was executed.")
    message: Optional[str] = Field(default=None, description="Human-readable verification result message.")


class OnChainRecord(BaseModel):
    """Typed representation of a DocumentIntegrity.getRecord() response."""

    document_id: str = Field(..., description="Document identifier used as the lookup key.")
    vault_id: str = Field(..., description="0x-prefixed bytes32 hex of the vault reference on-chain.")
    integrity_hash: str = Field(..., description="0x-prefixed bytes32 hex of the anchored document hash.")
    timestamp: int = Field(..., description="Unix epoch timestamp recorded by the EVM (block.timestamp).")
    recorder: str = Field(..., description="Ethereum address that submitted the recordHash transaction.")
    network: str = Field(..., description="Blockchain network label.")


class BlockchainHealthResponse(BaseModel):
    """Health and connectivity status for the configured blockchain provider."""

    provider: str = Field(..., description="Adapter type: 'ganache' or 'local'.")
    network: str = Field(..., description="Network label from settings.")
    connected: bool = Field(..., description="Whether the RPC endpoint is reachable.")
    available: bool = Field(..., description="Whether the adapter is ready to serve requests.")
    rpc_url: Optional[str] = Field(default=None, description="RPC endpoint URL (Ganache only).")
    chain_id: Optional[int] = Field(default=None, description="EVM chain ID (Ganache only).")
    block_number: Optional[int] = Field(default=None, description="Latest block number (Ganache only).")
    contract_address: Optional[str] = Field(default=None, description="Deployed contract address (Ganache only).")
    contract_owner: Optional[str] = Field(default=None, description="Contract owner() return value (Ganache only).")
    deployer_address: Optional[str] = Field(default=None, description="Deployer wallet address (Ganache only).")
    error: Optional[str] = Field(default=None, description="Error message if connection failed.")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Any extra adapter-specific fields.")
