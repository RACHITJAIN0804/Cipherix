"""
services/document_processing/chunker.py
-----------------------------------------
Deterministic text chunking for RAG pipeline.
"""

import hashlib
from dataclasses import dataclass
from typing import Optional

from app.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DocumentChunk:
    """In-memory representation of a document text chunk."""

    chunk_id: str
    document_id: str
    chunk_index: int
    character_count: int
    page_number: Optional[int]
    text: str


class TextChunker:
    """
    Splits text into deterministic, ordered chunks with configurable overlap.
    """

    def __init__(self, default_chunk_size: int = 500, default_chunk_overlap: int = 50) -> None:
        self._default_chunk_size: int = default_chunk_size
        self._default_chunk_overlap: int = default_chunk_overlap

    def compute_chunk_id(self, document_id: str, chunk_index: int, text: str) -> str:
        payload = f"{document_id}:{chunk_index}:{text}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]

    def chunk_text(
        self,
        text: str,
        document_id: str,
        chunk_size: int | None = None,
        chunk_overlap: int | None = None,
        page_blocks: list[tuple[str, Optional[int]]] | None = None,
    ) -> list[DocumentChunk]:
        size = chunk_size if chunk_size is not None and chunk_size > 0 else self._default_chunk_size
        overlap = chunk_overlap if chunk_overlap is not None and chunk_overlap >= 0 else self._default_chunk_overlap

        if overlap >= size:
            overlap = size // 2

        if not text or not text.strip():
            return []

        chunks: list[DocumentChunk] = []

        if page_blocks and len(page_blocks) > 0 and any(p is not None for _, p in page_blocks):
            # Paginated chunking for PDF
            idx = 0
            for block_text, page_num in page_blocks:
                sub_chunks = self._split_single_block(block_text, size, overlap)
                for sc_text in sub_chunks:
                    if not sc_text.strip():
                        continue
                    cid = self.compute_chunk_id(document_id, idx, sc_text)
                    chunks.append(
                        DocumentChunk(
                            chunk_id=cid,
                            document_id=document_id,
                            chunk_index=idx,
                            character_count=len(sc_text),
                            page_number=page_num,
                            text=sc_text,
                        )
                    )
                    idx += 1
        else:
            # Single-pass chunking for TXT / DOCX
            sc_texts = self._split_single_block(text, size, overlap)
            for idx, sc_text in enumerate(sc_texts):
                if not sc_text.strip():
                    continue
                cid = self.compute_chunk_id(document_id, idx, sc_text)
                chunks.append(
                    DocumentChunk(
                        chunk_id=cid,
                        document_id=document_id,
                        chunk_index=idx,
                        character_count=len(sc_text),
                        page_number=None,
                        text=sc_text,
                    )
                )

        logger.info(
            "Chunked document | document_id=%s | text_len=%d | chunk_count=%d | size=%d | overlap=%d",
            document_id,
            len(text),
            len(chunks),
            size,
            overlap,
        )
        return chunks

    def _split_single_block(self, text: str, chunk_size: int, chunk_overlap: int) -> list[str]:
        if len(text) <= chunk_size:
            return [text]

        chunks: list[str] = []
        start = 0
        text_len = len(text)

        while start < text_len:
            end = start + chunk_size
            if end >= text_len:
                chunks.append(text[start:])
                break

            # Try to break at paragraph boundary or sentence boundary (. / ? / ! / \n)
            best_break = -1
            search_window = text[start + (chunk_size // 2) : end]
            for delim in ("\n\n", "\n", ". ", "? ", "! "):
                pos = search_window.rfind(delim)
                if pos != -1:
                    best_break = start + (chunk_size // 2) + pos + len(delim)
                    break

            if best_break != -1 and best_break > start:
                chunk_str = text[start:best_break].strip()
                chunks.append(chunk_str)
                start = max(best_break - chunk_overlap, start + 1)
            else:
                chunks.append(text[start:end].strip())
                start = end - chunk_overlap

        return [c for c in chunks if c]
