
import hmac
import uuid
from datetime import UTC, datetime
from typing import Any, Dict, Optional

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
from app.services.audit_service import (
    AuditService,
    EVENT_BLOCKCHAIN_ANCHOR_FAILURE,
    EVENT_BLOCKCHAIN_ANCHOR_SUCCESS,
    EVENT_BLOCKCHAIN_VERIFY_MISMATCH,
    EVENT_BLOCKCHAIN_VERIFY_MISSING_RECORD,
    EVENT_BLOCKCHAIN_VERIFY_REQUEST,
    EVENT_BLOCKCHAIN_VERIFY_SUCCESS,
    EVENT_BLOCKCHAIN_VERIFY_UNAVAILABLE,
)
from app.services.blockchain.adapters.base import BlockchainAdapter
from app.services.blockchain.adapters.local import LocalBlockchainAdapter
from app.storage.document_manager import DocumentManager

logger = get_logger(__name__)


def _build_default_adapter() -> BlockchainAdapter:
    """Return the configured blockchain adapter.

    Selection logic:
      - ``BLOCKCHAIN_PROVIDER=ganache``  →  GanacheAdapter (live Solidity contract)
      - anything else                   →  LocalBlockchainAdapter (in-memory)
    """
    if settings.blockchain_provider == "ganache":
        try:
            from app.services.blockchain.adapters.ganache import GanacheAdapter
            adapter = GanacheAdapter.from_settings()
            if adapter.is_available():
                logger.info(
                    "BlockchainService using GanacheAdapter | rpc=%s | contract=%s",
                    settings.blockchain_rpc_url,
                    settings.blockchain_contract_address[:10] + "...",
                )
                return adapter
            logger.warning(
                "GanacheAdapter RPC endpoint unavailable; falling back to LocalBlockchainAdapter."
            )
        except Exception as exc:
            logger.warning(
                "GanacheAdapter initialisation failed (%s); falling back to LocalBlockchainAdapter.",
                exc,
            )

    logger.info("BlockchainService using LocalBlockchainAdapter (in-memory).")
    return LocalBlockchainAdapter(network=settings.blockchain_network)


class BlockchainService:

    def __init__(self, adapter: Optional[BlockchainAdapter] = None) -> None:
        self.adapter: BlockchainAdapter = adapter or _build_default_adapter()
        self._enc_mgr = EncryptionManager()

    # ------------------------------------------------------------------
    # Health / status
    # ------------------------------------------------------------------

    def get_health(self) -> Dict[str, Any]:
        """Return a health/status dict for the current blockchain connection.

        Returns a dict with at minimum:
          - provider: adapter type string
          - network: network label
          - connected: bool
          - available: bool (adapter.is_available())

        If the adapter exposes a ``health()`` method (e.g. GanacheAdapter),
        its full response is returned. Otherwise a minimal dict is built.
        """
        available = self.adapter.is_available()
        if hasattr(self.adapter, "health"):
            try:
                result = self.adapter.health()  # type: ignore[attr-defined]
                result.setdefault("available", available)
                return result
            except Exception as exc:
                logger.warning("Adapter health() raised: %s", exc)

        return {
            "provider": getattr(self.adapter, "_provider", "unknown"),
            "network": self.adapter.network_name,
            "connected": available,
            "available": available,
        }

    def get_privacy_reference(self, user_id: str, document_id: str) -> str:
        secret_bytes = settings.jwt_secret_key.encode("utf-8")
        msg = f"cipherix:privacy_ref:{user_id}:{document_id}".encode("utf-8")
        return hmac.new(secret_bytes, msg, "sha256").hexdigest()

    def _verify_document_ownership(
        self, db: Session, user_id: str, vault_id: str, document_id: str
    ) -> DocumentRecord:
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
        if not settings.blockchain_enabled:
            AuditService.log_event(
                db,
                user_id=user_id,
                action=EVENT_BLOCKCHAIN_ANCHOR_FAILURE,
                vault_id=vault_id,
                document_id=document_id,
                result_status="FAILED",
                details={"error": "Blockchain anchoring is currently disabled in configuration."},
            )
            raise BlockchainUnavailableError(
                "Blockchain anchoring is currently disabled in configuration."
            )

        if not self.adapter.is_available():
            AuditService.log_event(
                db,
                user_id=user_id,
                action=EVENT_BLOCKCHAIN_ANCHOR_FAILURE,
                vault_id=vault_id,
                document_id=document_id,
                result_status="FAILED",
                details={"error": f"Blockchain network '{self.adapter.network_name}' is unavailable."},
            )
            raise BlockchainUnavailableError(
                f"Blockchain network '{self.adapter.network_name}' is unavailable."
            )

        doc = self._verify_document_ownership(db, user_id, vault_id, document_id)

        integrity_hash = doc.integrity_hash
        if not integrity_hash:
            vault_root = settings.VAULT_DIR / vault_id
            doc_mgr = DocumentManager(vault_root)
            try:
                ciphertext = doc_mgr.read_blob(document_id, vault_id)
                integrity_hash = self._enc_mgr.compute_sha256(ciphertext)
                doc.integrity_hash = integrity_hash
                db.commit()
            except Exception as err:
                AuditService.log_event(
                    db,
                    user_id=user_id,
                    action=EVENT_BLOCKCHAIN_ANCHOR_FAILURE,
                    vault_id=vault_id,
                    document_id=document_id,
                    result_status="FAILED",
                    details={"error": f"Missing integrity metadata: {err}"},
                )
                raise MissingIntegrityMetadataError(
                    f"Document '{document_id}' has no integrity hash and blob cannot be read: {err}"
                ) from err

        privacy_ref = self.get_privacy_reference(user_id, document_id)

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
                vault_id=existing_record.vault_id,
                privacy_reference=existing_record.privacy_reference,
                integrity_hash=existing_record.integrity_hash,
                network=existing_record.network,
                tx_hash=existing_record.tx_hash,
                block_number=existing_record.block_number,
                status=existing_record.status,
                anchored_at=existing_record.created_at,
                last_verified_at=existing_record.last_verified_at,
                last_verification_result=existing_record.last_verification_result,
                error_message=existing_record.error_message,
            )

        try:
            receipt = self.adapter.anchor_hash(
                privacy_reference=privacy_ref, integrity_hash=integrity_hash
            )
        except Exception as exc:
            AuditService.log_event(
                db,
                user_id=user_id,
                action=EVENT_BLOCKCHAIN_ANCHOR_FAILURE,
                vault_id=vault_id,
                document_id=document_id,
                result_status="FAILED",
                details={"error": str(exc), "network": getattr(self.adapter, "network_name", "unknown")},
            )
            raise

        anchor_id = str(uuid.uuid4())
        record = BlockchainAnchorRecord(
            id=anchor_id,
            document_id=document_id,
            vault_id=vault_id,
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

        AuditService.log_event(
            db,
            user_id=user_id,
            action=EVENT_BLOCKCHAIN_ANCHOR_SUCCESS,
            vault_id=vault_id,
            document_id=document_id,
            result_status="SUCCESS",
            details={
                "tx_hash": record.tx_hash,
                "block_number": record.block_number,
                "network": record.network,
                "integrity_hash": record.integrity_hash,
                "privacy_reference": record.privacy_reference,
            },
        )

        logger.info(
            "Blockchain anchor created | user_id=%s | document_id=%s | vault_id=%s | tx_hash=%s",
            user_id,
            document_id,
            vault_id,
            record.tx_hash[:16] + "...",
        )

        return AnchorResponse(
            anchor_id=record.id,
            document_id=record.document_id,
            vault_id=record.vault_id,
            privacy_reference=record.privacy_reference,
            integrity_hash=record.integrity_hash,
            network=record.network,
            tx_hash=record.tx_hash,
            block_number=record.block_number,
            status=record.status,
            anchored_at=record.created_at,
            last_verified_at=record.last_verified_at,
            last_verification_result=record.last_verification_result,
            error_message=record.error_message,
        )

    def verify_document_anchor(
        self, db: Session, user_id: str, vault_id: str, document_id: str
    ) -> VerifyAnchorResponse:
        AuditService.log_event(
            db,
            user_id=user_id,
            action=EVENT_BLOCKCHAIN_VERIFY_REQUEST,
            vault_id=vault_id,
            document_id=document_id,
            result_status="SUCCESS",
            details={"event": "Document integrity verification initiated"},
        )

        if not settings.blockchain_enabled:
            AuditService.log_event(
                db,
                user_id=user_id,
                action=EVENT_BLOCKCHAIN_VERIFY_UNAVAILABLE,
                vault_id=vault_id,
                document_id=document_id,
                result_status="FAILED",
                details={"error": "Blockchain feature is disabled in configuration."},
            )
            raise BlockchainUnavailableError("Blockchain feature is disabled in configuration.")

        if not self.adapter.is_available():
            AuditService.log_event(
                db,
                user_id=user_id,
                action=EVENT_BLOCKCHAIN_VERIFY_UNAVAILABLE,
                vault_id=vault_id,
                document_id=document_id,
                result_status="FAILED",
                details={"error": f"Blockchain network '{self.adapter.network_name}' is currently unavailable."},
            )
            raise BlockchainUnavailableError(
                f"Blockchain network '{self.adapter.network_name}' is currently unavailable."
            )

        doc = self._verify_document_ownership(db, user_id, vault_id, document_id)

        privacy_ref = self.get_privacy_reference(user_id, document_id)

        vault_root = settings.VAULT_DIR / vault_id
        doc_mgr = DocumentManager(vault_root)
        try:
            ciphertext = doc_mgr.read_blob(document_id, vault_id)
            current_hash = self._enc_mgr.compute_sha256(ciphertext)
        except Exception as err:
            raise DocumentNotFoundError(
                f"Encrypted blob for document '{document_id}' cannot be read or is missing on disk: {err}"
            ) from err

        stored_hash = doc.integrity_hash or ""
        integrity_match = bool(stored_hash) and hmac.compare_digest(stored_hash, current_hash)

        anchor_record = (
            db.query(BlockchainAnchorRecord)
            .filter(BlockchainAnchorRecord.document_id == document_id)
            .first()
        )

        if not anchor_record:
            AuditService.log_event(
                db,
                user_id=user_id,
                action=EVENT_BLOCKCHAIN_VERIFY_MISSING_RECORD,
                vault_id=vault_id,
                document_id=document_id,
                result_status="FAILED",
                details={"error": f"No blockchain integrity anchor record found for document '{document_id}'."},
            )
            raise AnchorNotFoundError(
                f"No blockchain integrity anchor record found for document '{document_id}'."
            )

        blockchain_hash: Optional[str] = None
        blockchain_match: bool = False
        network = anchor_record.network
        tx_hash: Optional[str] = anchor_record.tx_hash
        anchored_at: Optional[datetime] = anchor_record.created_at

        if hasattr(self.adapter, "get_anchor_by_reference"):
            bc_data = self.adapter.get_anchor_by_reference(  # type: ignore[attr-defined]
                anchor_record.privacy_reference
            )
        else:
            bc_data = self.adapter.get_anchor(anchor_record.tx_hash)

        if bc_data:
            blockchain_hash = bc_data.get("integrity_hash")
            if blockchain_hash:
                blockchain_match = hmac.compare_digest(current_hash, blockchain_hash)

        verified = integrity_match and blockchain_match
        now_utc = datetime.now(UTC)

        message = (
            "Document integrity successfully verified against blockchain record."
            if verified
            else "Document verification failed: Hash mismatch detected between disk ciphertext and on-chain record."
        )

        anchor_record.last_verified_at = now_utc
        anchor_record.last_verification_result = verified
        if not verified:
            anchor_record.error_message = (
                "Hash mismatch detected: local file hash does not match on-chain anchor."
                if blockchain_hash
                else "On-chain record not found or blockchain response invalid."
            )
        else:
            anchor_record.error_message = None

        try:
            db.commit()
            db.refresh(anchor_record)
        except Exception as exc:
            logger.warning("Failed to persist verification result: %s", exc)
            db.rollback()

        if verified:
            AuditService.log_event(
                db,
                user_id=user_id,
                action=EVENT_BLOCKCHAIN_VERIFY_SUCCESS,
                vault_id=vault_id,
                document_id=document_id,
                result_status="SUCCESS",
                details={
                    "tx_hash": tx_hash,
                    "network": network,
                    "verified": True,
                    "integrity_match": True,
                    "blockchain_match": True,
                },
            )
        else:
            AuditService.log_event(
                db,
                user_id=user_id,
                action=EVENT_BLOCKCHAIN_VERIFY_MISMATCH,
                vault_id=vault_id,
                document_id=document_id,
                result_status="FAILED",
                details={
                    "tx_hash": tx_hash,
                    "network": network,
                    "verified": False,
                    "integrity_match": integrity_match,
                    "blockchain_match": blockchain_match,
                    "error": message,
                },
            )

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
            current_hash=current_hash,
            blockchain_hash=blockchain_hash,
            integrity_match=integrity_match,
            blockchain_match=blockchain_match,
            verified=verified,
            network=network,
            tx_hash=tx_hash,
            anchored_at=anchored_at,
            verified_at=now_utc,
            message=message,
        )

    def get_document_anchor(
        self, db: Session, user_id: str, vault_id: str, document_id: str
    ) -> AnchorResponse:
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
            vault_id=record.vault_id,
            privacy_reference=record.privacy_reference,
            integrity_hash=record.integrity_hash,
            network=record.network,
            tx_hash=record.tx_hash,
            block_number=record.block_number,
            status=record.status,
            anchored_at=record.created_at,
            last_verified_at=record.last_verified_at,
            last_verification_result=record.last_verification_result,
            error_message=record.error_message,
        )
