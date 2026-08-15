"""
services/search_service.py
---------------------------
Core service orchestrating vault-isolated semantic vector search.
"""

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    VaultAccessDeniedError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.database.models import Document as DocumentRecord, Vault as VaultRecord
from app.schemas.search import SearchRequest, SearchResponse, SearchResultItem
from app.services.embedding_service import EmbeddingService
from app.services.vector_store import VectorStore

logger = get_logger(__name__)


class SearchService:
    """
    Service for executing vault-authorized semantic search requests.
    """

    def __init__(
        self,
        embedding_service: EmbeddingService | None = None,
        vector_store: VectorStore | None = None,
    ) -> None:
        self._embedding_service = embedding_service or EmbeddingService()
        self._vector_store = vector_store or VectorStore()

    def search(
        self,
        request: SearchRequest,
        user_id: str,
        db: Session,
    ) -> SearchResponse:
        """
        Execute semantic search strictly isolated to the user's authorized vault.

        Flow
        ----
        1. Authorize user vault ownership in SQLite DB.
        2. Validate query text string.
        3. Generate query text embedding via EmbeddingService.
        4. Execute vector similarity search strictly filtered by vault_id.
        5. Enrich matching chunks with original document filenames from SQLite.
        6. Return SearchResponse.
        """
        vault_id = request.vault_id
        query_text = request.query.strip() if request.query else ""
        top_k = request.top_k or settings.search_default_top_k

        # 1. Authorize User Vault Ownership
        vault_rec = db.query(VaultRecord).filter(VaultRecord.id == vault_id).first()
        if vault_rec is None:
            raise VaultNotFoundError(f"Vault '{vault_id}' not found.")

        if vault_rec.user_id != user_id:
            logger.warning(
                "Unauthorized vector search attempt | user_id=%s | vault_id=%s",
                user_id,
                vault_id,
            )
            raise VaultAccessDeniedError(
                "Access denied.",
                detail=f"User '{user_id}' does not own vault '{vault_id}'.",
            )

        if not query_text:
            return SearchResponse(
                vault_id=vault_id,
                query=request.query,
                total_results=0,
                results=[],
            )

        # 2. Generate Query Embedding
        query_embedding = self._embedding_service.generate_embedding(query_text)

        # 3. Perform Vault-Filtered Vector Search
        raw_matches = self._vector_store.search_vault(
            query_embedding=query_embedding,
            vault_id=vault_id,
            top_k=top_k,
        )

        if not raw_matches:
            return SearchResponse(
                vault_id=vault_id,
                query=request.query,
                total_results=0,
                results=[],
            )

        # 4. Enrich with Document Filenames from DB
        doc_ids = {m["document_id"] for m in raw_matches if m.get("document_id")}
        doc_records = (
            db.query(DocumentRecord.id, DocumentRecord.original_filename)
            .filter(DocumentRecord.id.in_(doc_ids), DocumentRecord.vault_id == vault_id)
            .all()
        )
        doc_filename_map = {r.id: r.original_filename for r in doc_records}

        results: list[SearchResultItem] = []
        for match in raw_matches:
            doc_id = match.get("document_id", "")
            filename = doc_filename_map.get(doc_id, "")
            results.append(
                SearchResultItem(
                    chunk_id=match["chunk_id"],
                    document_id=doc_id,
                    vault_id=vault_id,
                    chunk_index=match["chunk_index"],
                    character_count=match["character_count"],
                    page_number=match.get("page_number"),
                    similarity_score=match["similarity_score"],
                    text=match["text"],
                    original_filename=filename,
                )
            )

        logger.info(
            "Semantic search executed | user_id=%s | vault_id=%s | total_results=%d",
            user_id,
            vault_id,
            len(results),
        )

        return SearchResponse(
            vault_id=vault_id,
            query=request.query,
            total_results=len(results),
            results=results,
        )
