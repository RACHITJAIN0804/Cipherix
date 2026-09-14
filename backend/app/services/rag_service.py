
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    DocumentProcessingError,
    RAGEmptyQueryError,
    RAGNoContextError,
    VaultAccessDeniedError,
    VaultNotFoundError,
)
from app.core.logger import get_logger
from app.database.models import Document as DocumentRecord, Vault as VaultRecord
from app.schemas.rag import RAGRequest, RAGResponse, RAGSource
from app.services.context_builder import ContextBuilder
from app.services.embedding_service import EmbeddingService
from app.services.llm_service import LLMService, get_llm_service
from app.services.vector_store import VectorStore

logger = get_logger(__name__)


class RAGService:

    def __init__(
        self,
        embedding_service: EmbeddingService | None = None,
        vector_store: VectorStore | None = None,
        context_builder: ContextBuilder | None = None,
        llm_service: LLMService | None = None,
    ) -> None:
        self._embedding_service = embedding_service or EmbeddingService()
        self._vector_store = vector_store or VectorStore()
        self._context_builder = context_builder or ContextBuilder()
        self._llm_service = llm_service or get_llm_service()

    def query(
        self,
        request: RAGRequest,
        user_id: str,
        db: Session,
    ) -> RAGResponse:
        vault_id = request.vault_id
        query_text = request.query.strip() if request.query else ""


        top_k = request.top_k or settings.rag_max_chunks
        min_similarity = (
            request.min_similarity
            if request.min_similarity is not None
            else settings.rag_min_similarity
        )
        max_context_chars = settings.rag_max_context_chars


        if not query_text:
            raise RAGEmptyQueryError("Query must not be empty.")


        vault_rec = db.query(VaultRecord).filter(VaultRecord.id == vault_id).first()
        if vault_rec is None:
            raise VaultNotFoundError(f"Vault '{vault_id}' not found.")

        if vault_rec.user_id != user_id:
            logger.warning(
                "Unauthorized RAG query attempt | user_id=%s | vault_id=%s",
                user_id,
                vault_id,
            )
            raise VaultAccessDeniedError(
                "Access denied.",
                detail=f"User '{user_id}' does not own vault '{vault_id}'.",
            )


        try:
            query_embedding = self._embedding_service.generate_embedding(query_text)
        except DocumentProcessingError:
            logger.error(
                "RAG embedding failure | user_id=%s | vault_id=%s",
                user_id,
                vault_id,
            )
            raise


        try:
            raw_matches = self._vector_store.search_vault(
                query_embedding=query_embedding,
                vault_id=vault_id,
                top_k=top_k,
            )
        except DocumentProcessingError:
            logger.error(
                "RAG vector search failure | user_id=%s | vault_id=%s",
                user_id,
                vault_id,
            )
            raise


        doc_filename_map: dict[str, str] = {}
        if raw_matches:
            doc_ids = {m["document_id"] for m in raw_matches if m.get("document_id")}
            doc_records = (
                db.query(DocumentRecord.id, DocumentRecord.original_filename)
                .filter(
                    DocumentRecord.id.in_(doc_ids),
                    DocumentRecord.vault_id == vault_id,
                )
                .all()
            )
            doc_filename_map = {r.id: r.original_filename for r in doc_records}


        ctx_builder = ContextBuilder(
            max_chunks=top_k,
            max_context_chars=max_context_chars,
            min_similarity=min_similarity,
        )
        context_result = ctx_builder.build(
            search_results=raw_matches,
            doc_filename_map=doc_filename_map,
        )

        if context_result.chunks_used == 0:
            logger.info(
                "RAG: no chunks met similarity threshold | user_id=%s | vault_id=%s | threshold=%.2f",
                user_id,
                vault_id,
                min_similarity,
            )
            raise RAGNoContextError(
                "No relevant document chunks found above the similarity threshold.",
                detail=(
                    f"No chunks from vault '{vault_id}' scored above "
                    f"{min_similarity:.2f} similarity for this query."
                ),
            )


        answer = self._llm_service.generate(
            context=context_result.context_text,
            question=query_text,
        )

        logger.info(
            "RAG query completed | user_id=%s | vault_id=%s | chunks_used=%d",
            user_id,
            vault_id,
            context_result.chunks_used,
        )


        sources = [
            RAGSource(
                document_id=src.document_id,
                filename=src.filename,
                chunk_id=src.chunk_id,
                chunk_index=src.chunk_index,
                page_number=src.page_number,
                similarity=src.similarity,
            )
            for src in context_result.sources
        ]

        return RAGResponse(
            vault_id=vault_id,
            query=request.query,
            answer=answer,
            sources=sources,
            total_chunks_used=context_result.chunks_used,
            llm_model=self._llm_service.model_name,
        )
