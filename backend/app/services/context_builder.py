"""
services/context_builder.py
----------------------------
Context builder for the Cipherix RAG pipeline.

Converts raw semantic search results into a bounded, safely formatted
context string suitable for sending to a local LLM, along with source
citation metadata.

Design constraints
------------------
* Maximum chunk count (``max_chunks``) prevents flooding the LLM context.
* Maximum total characters (``max_context_chars``) enforces a hard ceiling.
* Minimum similarity threshold (``min_similarity``) filters low-confidence
  chunks before they can pollute the answer.
* Each chunk is wrapped in explicit ``[DOCUMENT EXCERPT N]`` delimiters
  to support the LLM's prompt-injection defense.
* Source metadata is preserved for citation in the API response.

Privacy
-------
No document text is logged by this module.
"""

from dataclasses import dataclass, field

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ContextSource:
    """Source citation for a single document chunk used in the RAG context."""

    document_id: str
    filename: str | None
    chunk_id: str
    chunk_index: int
    page_number: int | None
    similarity: float


@dataclass
class ContextResult:
    """Output of the ContextBuilder: formatted context text and source list."""

    context_text: str
    sources: list[ContextSource] = field(default_factory=list)
    total_chars: int = 0
    chunks_used: int = 0


class ContextBuilder:
    """
    Assembles LLM context from ranked semantic search results.

    Parameters
    ----------
    max_chunks:
        Maximum number of chunks to include (default: ``settings.rag_max_chunks``).
    max_context_chars:
        Hard ceiling on total context characters (default: ``settings.rag_max_context_chars``).
    min_similarity:
        Minimum cosine similarity for a chunk to be included
        (default: ``settings.rag_min_similarity``).
    """

    def __init__(
        self,
        max_chunks: int | None = None,
        max_context_chars: int | None = None,
        min_similarity: float | None = None,
    ) -> None:
        self.max_chunks: int = max_chunks or settings.rag_max_chunks
        self.max_context_chars: int = max_context_chars or settings.rag_max_context_chars
        self.min_similarity: float = (
            min_similarity if min_similarity is not None else settings.rag_min_similarity
        )

    def build(
        self,
        search_results: list[dict],
        doc_filename_map: dict[str, str] | None = None,
    ) -> ContextResult:
        """
        Build a bounded context string from semantic search results.

        Parameters
        ----------
        search_results:
            List of result dicts from ``VectorStore.search_vault()``.
            Each dict contains: chunk_id, document_id, vault_id,
            chunk_index, character_count, page_number, similarity_score, text.
        doc_filename_map:
            Optional mapping of document_id → original_filename for citations.

        Returns
        -------
        ContextResult
            Assembled context text and source citation list.
        """
        if doc_filename_map is None:
            doc_filename_map = {}

        # 1. Filter by similarity threshold
        eligible = [
            r for r in search_results
            if r.get("similarity_score", 0.0) >= self.min_similarity
        ]

        # 2. Cap chunk count
        eligible = eligible[: self.max_chunks]

        if not eligible:
            logger.info(
                "ContextBuilder: no chunks met similarity threshold %.2f",
                self.min_similarity,
            )
            return ContextResult(context_text="", sources=[], total_chars=0, chunks_used=0)

        # 3. Assemble context with delimiters and enforce character ceiling
        excerpt_parts: list[str] = []
        sources: list[ContextSource] = []
        total_chars = 0

        for idx, chunk in enumerate(eligible, start=1):
            chunk_text: str = chunk.get("text", "").strip()
            if not chunk_text:
                continue

            doc_id: str = chunk.get("document_id", "")
            filename: str | None = doc_filename_map.get(doc_id)
            source_label = filename or f"document:{doc_id[:8]}"

            page = chunk.get("page_number")
            page_info = f" | page {page}" if page is not None else ""

            header = (
                f"[DOCUMENT EXCERPT {idx} | source: {source_label}"
                f" | chunk {chunk.get('chunk_index', idx - 1)}{page_info}]"
            )
            footer = f"[END EXCERPT {idx}]"
            block = f"{header}\n{chunk_text}\n{footer}"

            # Enforce character ceiling — truncate block if needed
            remaining = self.max_context_chars - total_chars
            if remaining <= 0:
                logger.info(
                    "ContextBuilder: character ceiling %d reached after %d chunks",
                    self.max_context_chars,
                    len(sources),
                )
                break

            if len(block) > remaining:
                # Truncate the chunk text to fit within the remaining budget
                budget_for_text = remaining - len(header) - len(footer) - 4  # "\n\n"
                if budget_for_text <= 0:
                    break
                chunk_text = chunk_text[:budget_for_text] + "…"
                block = f"{header}\n{chunk_text}\n{footer}"

            excerpt_parts.append(block)
            total_chars += len(block)

            sources.append(
                ContextSource(
                    document_id=doc_id,
                    filename=filename,
                    chunk_id=chunk.get("chunk_id", ""),
                    chunk_index=chunk.get("chunk_index", 0),
                    page_number=page,
                    similarity=round(chunk.get("similarity_score", 0.0), 4),
                )
            )

        context_text = "\n\n".join(excerpt_parts)

        logger.info(
            "ContextBuilder: assembled context | chunks=%d | chars=%d | min_sim=%.2f",
            len(sources),
            total_chars,
            self.min_similarity,
        )

        return ContextResult(
            context_text=context_text,
            sources=sources,
            total_chars=total_chars,
            chunks_used=len(sources),
        )
