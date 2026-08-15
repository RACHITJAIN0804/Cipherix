"""
services/document_processing/pipeline.py
-----------------------------------------
Coordinates secure in-memory document processing pipeline for Cipherix RAG.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    CipherixError,
    DocumentNotFoundError,
    DocumentProcessingError,
    IntegrityVerificationError,
    VaultAccessDeniedError,
    VaultLockedError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.database.models import Document as DocumentRecord, Vault as VaultRecord
from app.schemas.document import DocumentChunkMetadata, DocumentProcessingResponse
from app.security.encryption import EncryptionManager
from app.security.key_manager import KeyManager
from app.security.password_manager import PasswordManager
from app.services.document_processing.chunker import TextChunker
from app.services.document_processing.cleaner import TextCleaner
from app.services.document_processing.extractor import DocumentExtractor
from app.services.document_service import DocumentService
from app.storage.document_manager import DocumentManager

from app.vault.manifest import VaultManifest

logger = get_logger(__name__)


class DocumentProcessingPipeline:
    """
    Coordinates authorization, integrity verification, controlled in-memory
    decryption, text extraction, cleaning, chunking, and metadata persistence.
    """

    def __init__(self, vault_base_dir: Path | None = None) -> None:
        self._vault_base_dir: Path = vault_base_dir or settings.VAULT_DIR
        self._extractor = DocumentExtractor()
        self._cleaner = TextCleaner()
        self._chunker = TextChunker(
            default_chunk_size=settings.rag_chunk_size,
            default_chunk_overlap=settings.rag_chunk_overlap,
        )

    def process_document(
        self,
        vault_id: str,
        document_id: str,
        user_id: str,
        password: str,
        db: Session,
        chunk_size: int | None = None,
        chunk_overlap: int | None = None,
    ) -> DocumentProcessingResponse:
        """
        Process an encrypted document in memory.

        Parameters
        ----------
        vault_id:
            Target vault UUID.
        document_id:
            Target document UUID.
        user_id:
            Authenticated user UUID (must own the vault).
        password:
            Vault password used to unwrap the Vault Key.
        db:
            Database session.
        """
        vault_root = self._vault_base_dir / vault_id
        if not vault_root.is_dir():
            raise VaultNotFoundError(f"Vault '{vault_id}' not found.")

        # 1. Authorization & Vault Ownership Check
        vault_rec = db.query(VaultRecord).filter(VaultRecord.id == vault_id).first()
        if vault_rec is None or vault_rec.user_id != user_id:
            raise VaultAccessDeniedError(
                "Access denied.",
                detail=f"User '{user_id}' does not own vault '{vault_id}'.",
            )

        # 2. Check Document Record
        doc_rec = (
            db.query(DocumentRecord)
            .filter(DocumentRecord.id == document_id, DocumentRecord.vault_id == vault_id)
            .first()
        )
        if doc_rec is None:
            raise DocumentNotFoundError(
                f"Document '{document_id}' not found in vault '{vault_id}'.",
                detail=f"No document record found for id '{document_id}'.",
            )

        # 3. Verify Document Integrity
        doc_service = DocumentService(vault_base_dir=self._vault_base_dir)
        doc_service.verify_document(vault_id, document_id, db=db)



        # In-memory working buffers
        raw_decrypted_bytes: Optional[bytes] = None
        extracted_text: Optional[str] = None
        cleaned_text: Optional[str] = None

        try:
            # 4. Controlled In-Memory Decryption
            pwd_mgr = PasswordManager(vault_root)
            key_mgr = KeyManager(vault_root)
            enc_mgr = EncryptionManager()

            salt_hex, _ = pwd_mgr.read_metadata(vault_id)
            master_key = pwd_mgr.derive_master_key(password, salt_hex)

            key_meta = key_mgr.read(vault_id)
            ct_bytes = enc_mgr.decode_from_storage(key_meta.encrypted_vault_key, "encrypted_vault_key")
            nonce_bytes = enc_mgr.decode_from_storage(key_meta.nonce, "nonce")

            vault_key_bytes = enc_mgr.decrypt_vault_key(ct_bytes, master_key, nonce_bytes)

            doc_mgr = DocumentManager(vault_root)
            doc_meta = doc_mgr.read_metadata(document_id, vault_id)
            doc_nonce_bytes = enc_mgr.decode_from_storage(doc_meta.nonce, "nonce")

            encrypted_blob_path = vault_root / doc_rec.encrypted_path
            if not encrypted_blob_path.is_file():
                raise DocumentNotFoundError(f"Encrypted file blob missing for document '{document_id}'.")

            ciphertext_payload = encrypted_blob_path.read_bytes()
            raw_decrypted_bytes = enc_mgr.decrypt_bytes(
                ciphertext=ciphertext_payload,
                vault_key=vault_key_bytes,
                nonce=doc_nonce_bytes,
            )



            # 5. Text Extraction
            extracted_text, page_blocks = self._extractor.extract_text(
                content_bytes=raw_decrypted_bytes,
                filename=doc_rec.original_filename,
                mime_type=doc_rec.mime_type,
            )

            # 6. Text Cleaning
            cleaned_text = self._cleaner.clean(extracted_text)

            # 7. Deterministic Chunking
            chunks = self._chunker.chunk_text(
                text=cleaned_text,
                document_id=document_id,
                chunk_size=chunk_size,
                chunk_overlap=chunk_overlap,
                page_blocks=page_blocks,
            )

            # 8. Update SQLite Processing Metadata
            now = datetime.now(UTC)
            doc_rec.processing_status = "processed"
            doc_rec.extraction_version = "1.0"
            doc_rec.chunking_version = "1.0"
            doc_rec.chunk_count = len(chunks)
            doc_rec.processed_at = now
            db.commit()

            logger.info(
                "Document processing complete | vault_id=%s | document_id=%s | chunks=%d",
                vault_id,
                document_id,
                len(chunks),
            )

            chunk_schemas = [
                DocumentChunkMetadata(
                    chunk_id=c.chunk_id,
                    document_id=c.document_id,
                    chunk_index=c.chunk_index,
                    character_count=c.character_count,
                    page_number=c.page_number,
                    text=c.text,
                )
                for c in chunks
            ]

            return DocumentProcessingResponse(
                document_id=document_id,
                processing_status="processed",
                chunk_count=len(chunks),
                processed_at=now,
                extraction_version="1.0",
                chunking_version="1.0",
                chunks=chunk_schemas,
            )

        except Exception as exc:
            doc_rec.processing_status = "failed"
            try:
                db.commit()
            except Exception:
                db.rollback()
            logger.error("Processing pipeline failed | document_id=%s | error=%s", document_id, exc)
            if not isinstance(exc, CipherixError):
                raise DocumentProcessingError(
                    f"Document processing failed for '{document_id}': {exc}",
                    detail=str(exc),
                ) from exc
            raise

        finally:
            # 9. In-Memory Safe Cleanup
            raw_decrypted_bytes = None
            extracted_text = None
            cleaned_text = None
