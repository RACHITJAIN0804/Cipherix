"""
services/rag_service.py
------------------------
RAG pipeline orchestrator for Cipherix.

Coordinates the full Retrieval-Augmented Generation flow:

    JWT auth → vault authorization → query embedding → ChromaDB search
    → similarity threshold → context building → local LLM → grounded answer

Vault isolation is enforced at every step:
* Vault ownership is verified against the SQLite DB (user_id == current user).
* The ChromaDB query is hard-filtered by vault_id (VectorStore.search_vault).
* Only context retrieved from the authorized vault reaches the LLM.

Privacy
-------
* Document chunk text is never logged.
* Generated answers are never logged.
* Only safe metadata (user_id, vault_id, chunk counts) is logged.
"""

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
    """
    Orchestrates the RAG pipeline for vault-isolated question answering.

    Depends on EmbeddingService, VectorStore, ContextBuilder, and LLMService.
    The LLMService singleton is reused across requests to avoid reloading.
    """

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
        """
        Execute the full RAG pipeline for an authenticated, authorized user.

        Flow
        ----
        1. Validate query is non-empty.
        2. Authorize user vault ownership in SQLite.
        3. Generate query embedding (local Sentence Transformers).
        4. Search ChromaDB filtered by vault_id (vault isolation enforced).
        5. Apply similarity threshold; raise RAGNoContextError if no results.
        6. Build bounded context from qualifying chunks.
        7. Send context + question to local LLM (Ollama).
        8. Return RAGResponse with answer and source citations.

        Parameters
        ----------
        request:
            Validated RAGRequest containing vault_id, query, and options.
        user_id:
            Authenticated user's ID from JWT — never client-supplied.
        db:
            Active SQLAlchemy session.

        Returns
        -------
        RAGResponse
            Grounded answer with source document citations.

        Raises
        ------
        RAGEmptyQueryError:
            Query string is empty or whitespace-only.
        VaultNotFoundError:
            Vault does not exist.
        VaultAccessDeniedError:
            Vault belongs to a different user.
        RAGNoContextError:
            No chunks met the similarity threshold.
        DocumentProcessingError:
            Embedding or vector search failure.
        LLMUnavailableError / LLMTimeoutError / LLMGenerationError:
            LLM backend failures.
        """
        vault_id = request.vault_id
        query_text = request.query.strip() if request.query else ""

        # Resolve per-request overrides with settings defaults
        top_k = request.top_k or settings.rag_max_chunks
        min_similarity = (
            request.min_similarity
            if request.min_similarity is not None
            else settings.rag_min_similarity
        )
        max_context_chars = settings.rag_max_context_chars

        # Step 1 — Validate query
        if not query_text:
            raise RAGEmptyQueryError("Query must not be empty.")

        # Step 2 — Authorize vault ownership
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

        # Step 3 — Generate query embedding (local, private)
        try:
            query_embedding = self._embedding_service.generate_embedding(query_text)
        except DocumentProcessingError:
            logger.error(
                "RAG embedding failure | user_id=%s | vault_id=%s",
                user_id,
                vault_id,
            )
            raise

        # Step 4 — Vault-filtered vector search
        try:
            raw_matches = self._vector_store.search_vault(
                query_embedding=query_embedding,
                vault_id=vault_id,  # HARD vault isolation filter
                top_k=top_k,
            )
        except DocumentProcessingError:
            logger.error(
                "RAG vector search failure | user_id=%s | vault_id=%s",
                user_id,
                vault_id,
            )
            raise

        # Step 5 — Enrich with filenames from DB (vault-scoped query only)
        doc_filename_map: dict[str, str] = {}
        if raw_matches:
            doc_ids = {m["document_id"] for m in raw_matches if m.get("document_id")}
            doc_records = (
                db.query(DocumentRecord.id, DocumentRecord.original_filename)
                .filter(
                    DocumentRecord.id.in_(doc_ids),
                    DocumentRecord.vault_id == vault_id,  # vault isolation
                )
                .all()
            )
            doc_filename_map = {r.id: r.original_filename for r in doc_records}

        # Step 6 — Build bounded context (applies similarity threshold)
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

        # Step 7 — Generate answer via local LLM
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

        # Step 8 — Assemble response with source citations
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
