"""
schemas/blockchain.py
---------------------
Pydantic schemas for blockchain document integrity anchoring and verification.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class AnchorRequest(BaseModel):
    """Request payload to anchor a document's integrity hash on the blockchain."""

    vault_id: str = Field(..., description="UUID of the vault containing the document.")
    document_id: str = Field(..., description="UUID of the document to anchor.")


class AnchorResponse(BaseModel):
    """Response returned upon successful blockchain anchoring."""

    model_config = ConfigDict(from_attributes=True)

    anchor_id: str = Field(..., description="UUID of the internal anchor record.")
    document_id: str = Field(..., description="UUID of the anchored document.")
    privacy_reference: str = Field(..., description="Privacy-preserving reference hash.")
    integrity_hash: str = Field(..., description="Anchored SHA-256 integrity hash.")
    network: str = Field(..., description="Blockchain network name.")
    tx_hash: str = Field(..., description="Blockchain transaction hash / block reference.")
    block_number: int = Field(..., description="Block number on the ledger.")
    status: str = Field(..., description="Anchor status ('anchored', 'pending', 'failed').")
    anchored_at: datetime = Field(..., description="UTC timestamp when anchor was confirmed.")


class VerifyAnchorRequest(BaseModel):
    """Request payload to verify a document against its stored hash and blockchain anchor."""

    vault_id: str = Field(..., description="UUID of the vault containing the document.")
    document_id: str = Field(..., description="UUID of the document to verify.")


class VerifyAnchorResponse(BaseModel):
    """Structured response for document integrity and blockchain verification."""

    document_id: str = Field(..., description="UUID of verified document.")
    privacy_reference: str = Field(..., description="Privacy-preserving document reference.")
    stored_integrity_hash: str = Field(..., description="SHA-256 hash stored in DB metadata.")
    current_integrity_hash: str = Field(..., description="SHA-256 hash recalculated from disk ciphertext.")
    blockchain_hash: Optional[str] = Field(default=None, description="Hash retrieved from blockchain record.")
    integrity_match: bool = Field(..., description="Whether disk ciphertext hash matches stored DB hash.")
    blockchain_match: bool = Field(..., description="Whether disk ciphertext hash matches blockchain anchor.")
    verified: bool = Field(..., description="Overall verification result (true if both matches pass).")
    network: str = Field(..., description="Blockchain network label.")
    tx_hash: Optional[str] = Field(default=None, description="Blockchain transaction hash.")
    anchored_at: Optional[datetime] = Field(default=None, description="Timestamp of blockchain anchor.")
