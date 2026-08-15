"""
services/blockchain/blockchain_service.py
-----------------------------------------
Blockchain integrity and verification service layer for Cipherix.

Provides privacy-preserving document integrity hash anchoring, retrieval,
and multi-tier verification (Disk Ciphertext Hash vs. SQLite Metadata vs. Blockchain Ledger).
"""

import hmac
import uuid
from datetime import UTC, datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    AnchorNotFoundError,
    BlockchainUnavailableError,
    DocumentNotFoundError,
    MissingIntegrityMetadataError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.database.models import BlockchainAnchorRecord, Document as DocumentRecord, Vault as VaultRecord
from app.schemas.blockchain import AnchorResponse, VerifyAnchorResponse
from app.security.encryption import EncryptionManager
from app.services.blockchain.adapters.base import BlockchainAdapter
from app.services.blockchain.adapters.local import LocalBlockchainAdapter
from app.storage.document_manager import DocumentManager

logger = get_logger(__name__)


class BlockchainService:
    """
    Service managing document integrity hash anchoring and verification.
    """

    def __init__(self, adapter: Optional[BlockchainAdapter] = None) -> None:
        self.adapter: BlockchainAdapter = adapter or LocalBlockchainAdapter(
            network=settings.blockchain_network
        )
        self._enc_mgr = EncryptionManager()

    def get_privacy_reference(self, user_id: str, document_id: str) -> str:
        """
        Derive a privacy-preserving reference hash using secret-keyed SHA-256 HMAC.

        Ensures raw document UUIDs or internal filesystem references are never
        published directly on-chain.
        """
        secret_bytes = settings.jwt_secret_key.encode("utf-8")
        msg = f"cipherix:privacy_ref:{user_id}:{document_id}".encode("utf-8")
        return hmac.new(secret_bytes, msg, "sha256").hexdigest()

    def _verify_document_ownership(
        self, db: Session, user_id: str, vault_id: str, document_id: str
    ) -> DocumentRecord:
        """
        Verify that vault exists, belongs to user_id, and document belongs to vault.

        Raises
        ------
        VaultNotFoundError
            If vault does not exist or belong to user.
        DocumentNotFoundError
            If document does not exist or belong to vault.
        """
        vault = db.get(VaultRecord, vault_id)
        if vault is None or (vault.user_id is not None and vault.user_id != user_id):
            raise VaultNotFoundError(f"Vault '{vault_id}' not found.")

        doc = db.get(DocumentRecord, document_id)
        if doc is None or doc.vault_id != vault_id:
            raise DocumentNotFoundError(f"Document '{document_id}' not found in vault '{vault_id}'.")

        return doc

    def anchor_document(
        self, db: Session, user_id: str, vault_id: str, document_id: str
    ) -> AnchorResponse:
        """
        Anchor document's SHA-256 integrity hash on the blockchain.

        Integrity hash is obtained authoritatively from the document record / ciphertext.
        Client-supplied hashes are NEVER trusted.
        """
        if not settings.blockchain_enabled:
            raise BlockchainUnavailableError(
                "Blockchain anchoring is currently disabled in configuration."
            )

        if not self.adapter.is_available():
            raise BlockchainUnavailableError(
                f"Blockchain network '{self.adapter.network_name}' is unavailable."
            )

        doc = self._verify_document_ownership(db, user_id, vault_id, document_id)

        # Obtain authoritative document integrity hash
        integrity_hash = doc.integrity_hash
        if not integrity_hash:
            # Attempt recalculation from disk blob
            vault_root = settings.VAULT_DIR / vault_id
            doc_mgr = DocumentManager(vault_root)
            try:
                ciphertext = doc_mgr.read_blob(document_id, vault_id)
                integrity_hash = self._enc_mgr.compute_sha256(ciphertext)
                doc.integrity_hash = integrity_hash
                db.commit()
            except Exception as err:
                raise MissingIntegrityMetadataError(
                    f"Document '{document_id}' has no integrity hash and blob cannot be read: {err}"
                ) from err

        privacy_ref = self.get_privacy_reference(user_id, document_id)

        # Check if record already exists in DB
        existing_record = (
            db.query(BlockchainAnchorRecord)
            .filter(BlockchainAnchorRecord.document_id == document_id)
            .first()
        )
        if existing_record:
            logger.info("Document '%s' already anchored. Returning existing anchor record.", document_id)
            return AnchorResponse(
                anchor_id=existing_record.id,
                document_id=existing_record.document_id,
                privacy_reference=existing_record.privacy_reference,
                integrity_hash=existing_record.integrity_hash,
                network=existing_record.network,
                tx_hash=existing_record.tx_hash,
                block_number=existing_record.block_number,
                status=existing_record.status,
                anchored_at=existing_record.created_at,
            )

        # Perform blockchain anchoring via adapter
        receipt = self.adapter.anchor_hash(
            privacy_reference=privacy_ref, integrity_hash=integrity_hash
        )

        anchor_id = str(uuid.uuid4())
        record = BlockchainAnchorRecord(
            id=anchor_id,
            document_id=document_id,
            privacy_reference=privacy_ref,
            integrity_hash=integrity_hash,
            network=receipt.get("network", self.adapter.network_name),
            tx_hash=receipt["tx_hash"],
            block_number=receipt.get("block_number", 1),
            status=receipt.get("status", "anchored"),
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        logger.info(
            "Blockchain anchor created | user_id=%s | document_id=%s | tx_hash=%s",
            user_id,
            document_id,
            record.tx_hash[:16] + "...",
        )

        return AnchorResponse(
            anchor_id=record.id,
            document_id=record.document_id,
            privacy_reference=record.privacy_reference,
            integrity_hash=record.integrity_hash,
            network=record.network,
            tx_hash=record.tx_hash,
            block_number=record.block_number,
            status=record.status,
            anchored_at=record.created_at,
        )

    def verify_document_anchor(
        self, db: Session, user_id: str, vault_id: str, document_id: str
    ) -> VerifyAnchorResponse:
        """
        Perform 3-tier verification:
        1. Recalculate SHA-256 directly from encrypted disk blob.
        2. Compare against stored SQLite DB integrity_hash.
        3. Compare against Blockchain network anchored hash.
        """
        doc = self._verify_document_ownership(db, user_id, vault_id, document_id)
        privacy_ref = self.get_privacy_reference(user_id, document_id)

        # 1. Recalculate hash from disk ciphertext
        vault_root = settings.VAULT_DIR / vault_id
        doc_mgr = DocumentManager(vault_root)
        try:
            ciphertext = doc_mgr.read_blob(document_id, vault_id)
            current_hash = self._enc_mgr.compute_sha256(ciphertext)
        except Exception as err:
            raise DocumentNotFoundError(
                f"Encrypted blob for document '{document_id}' cannot be read: {err}"
            ) from err

        stored_hash = doc.integrity_hash or ""
        integrity_match = bool(stored_hash) and hmac.compare_digest(stored_hash, current_hash)

        # Fetch anchor record from DB
        anchor_record = (
            db.query(BlockchainAnchorRecord)
            .filter(BlockchainAnchorRecord.document_id == document_id)
            .first()
        )

        blockchain_hash: Optional[str] = None
        blockchain_match: bool = False
        network = self.adapter.network_name
        tx_hash: Optional[str] = None
        anchored_at: Optional[datetime] = None

        if anchor_record:
            network = anchor_record.network
            tx_hash = anchor_record.tx_hash
            anchored_at = anchor_record.created_at

            if self.adapter.is_available():
                bc_data = self.adapter.get_anchor(anchor_record.tx_hash)
                if bc_data:
                    blockchain_hash = bc_data.get("integrity_hash")
                    if blockchain_hash:
                        blockchain_match = hmac.compare_digest(current_hash, blockchain_hash)

        verified = integrity_match and blockchain_match

        logger.info(
            "Blockchain verification | doc_id=%s | integrity_match=%s | blockchain_match=%s | verified=%s",
            document_id,
            integrity_match,
            blockchain_match,
            verified,
        )

        return VerifyAnchorResponse(
            document_id=document_id,
            privacy_reference=privacy_ref,
            stored_integrity_hash=stored_hash,
            current_integrity_hash=current_hash,
            blockchain_hash=blockchain_hash,
            integrity_match=integrity_match,
            blockchain_match=blockchain_match,
            verified=verified,
            network=network,
            tx_hash=tx_hash,
            anchored_at=anchored_at,
        )

    def get_document_anchor(
        self, db: Session, user_id: str, vault_id: str, document_id: str
    ) -> AnchorResponse:
        """
        Retrieve anchor record for document.
        """
        self._verify_document_ownership(db, user_id, vault_id, document_id)

        record = (
            db.query(BlockchainAnchorRecord)
            .filter(BlockchainAnchorRecord.document_id == document_id)
            .first()
        )

        if record is None:
            raise AnchorNotFoundError(
                f"No blockchain anchor found for document '{document_id}'."
            )

        return AnchorResponse(
            anchor_id=record.id,
            document_id=record.document_id,
            privacy_reference=record.privacy_reference,
            integrity_hash=record.integrity_hash,
            network=record.network,
            tx_hash=record.tx_hash,
            block_number=record.block_number,
            status=record.status,
            anchored_at=record.created_at,
        )
