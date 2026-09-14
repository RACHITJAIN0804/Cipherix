
from dataclasses import dataclass, field

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ContextSource:

    document_id: str
    filename: str | None
    chunk_id: str
    chunk_index: int
    page_number: int | None
    similarity: float


@dataclass
class ContextResult:

    context_text: str
    sources: list[ContextSource] = field(default_factory=list)
    total_chars: int = 0
    chunks_used: int = 0


class ContextBuilder:

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
        if doc_filename_map is None:
            doc_filename_map = {}


        eligible = [
            r for r in search_results
            if r.get("similarity_score", 0.0) >= self.min_similarity
        ]


        eligible = eligible[: self.max_chunks]

        if not eligible:
            logger.info(
                "ContextBuilder: no chunks met similarity threshold %.2f",
                self.min_similarity,
            )
            return ContextResult(context_text="", sources=[], total_chars=0, chunks_used=0)


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


            remaining = self.max_context_chars - total_chars
            if remaining <= 0:
                logger.info(
                    "ContextBuilder: character ceiling %d reached after %d chunks",
                    self.max_context_chars,
                    len(sources),
                )
                break

            if len(block) > remaining:

                budget_for_text = remaining - len(header) - len(footer) - 4
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
