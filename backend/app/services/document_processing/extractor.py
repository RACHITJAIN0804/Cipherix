"""
services/document_processing/extractor.py
-------------------------------------------
Text extraction service for TXT, PDF, and DOCX documents.
"""

import io
from pathlib import Path
from typing import Optional

import pypdf
import docx

from app.core.exceptions import (
    DocumentExtractionError,
    EmptyDocumentError,
    UnsupportedFileTypeError,
)
from app.core.logger import get_logger

logger = get_logger(__name__)

_SUPPORTED_EXTENSIONS: set[str] = {".txt", ".pdf", ".docx"}
_SUPPORTED_MIME_TYPES: set[str] = {
    "text/plain",
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


class DocumentExtractor:
    """
    Extracts raw text and optional page associations from document bytes.
    """

    def extract_text(
        self,
        content_bytes: bytes,
        filename: str,
        mime_type: str | None = None,
    ) -> tuple[str, list[tuple[str, Optional[int]]]]:
        """
        Extract text from file content bytes.

        Returns
        -------
        tuple[str, list[tuple[str, Optional[int]]]]
            A tuple of (full_raw_text, text_blocks_with_page_numbers).
        """
        ext = Path(filename).suffix.lower()

        if ext not in _SUPPORTED_EXTENSIONS and (
            not mime_type or mime_type.lower() not in _SUPPORTED_MIME_TYPES
        ):
            raise UnsupportedFileTypeError(
                f"Unsupported file format '{ext}' for filename '{filename}'.",
                detail=f"File extension '{ext}' (MIME type '{mime_type}') is not supported for text extraction.",
            )

        if not content_bytes or len(content_bytes) == 0:
            raise EmptyDocumentError(
                f"Document '{filename}' is empty (0 bytes).",
                detail="Cannot extract text from a zero-byte document.",
            )

        if ext == ".txt" or mime_type == "text/plain":
            return self._extract_txt(content_bytes, filename)
        elif ext == ".pdf" or mime_type == "application/pdf":
            return self._extract_pdf(content_bytes, filename)
        elif ext == ".docx" or mime_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
            return self._extract_docx(content_bytes, filename)
        else:
            raise UnsupportedFileTypeError(
                f"Unsupported file format '{ext}'.",
                detail=f"File extension '{ext}' is not supported.",
            )

    def _extract_txt(self, content_bytes: bytes, filename: str) -> tuple[str, list[tuple[str, Optional[int]]]]:
        try:
            text = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = content_bytes.decode("latin-1")
            except Exception as exc:
                raise DocumentExtractionError(
                    f"Failed to decode text file '{filename}': {exc}",
                    detail=f"Text file '{filename}' could not be decoded as UTF-8 or Latin-1.",
                ) from exc

        if not text.strip():
            raise EmptyDocumentError(
                f"Text file '{filename}' contains no text.",
                detail=f"Extracted content from '{filename}' is empty or whitespace only.",
            )

        logger.info("Extracted text from TXT file | filename=%s | chars=%d", filename, len(text))
        return text, [(text, None)]

    def _extract_pdf(self, content_bytes: bytes, filename: str) -> tuple[str, list[tuple[str, Optional[int]]]]:
        try:
            reader = pypdf.PdfReader(io.BytesIO(content_bytes))
            blocks: list[tuple[str, Optional[int]]] = []
            full_text_parts: list[str] = []

            for page_num, page in enumerate(reader.pages, start=1):
                page_text = page.extract_text() or ""
                if page_text.strip():
                    blocks.append((page_text, page_num))
                    full_text_parts.append(page_text)

            full_text = "\n\n".join(full_text_parts)
            if not full_text.strip():
                raise EmptyDocumentError(
                    f"PDF file '{filename}' contains no extractable text.",
                    detail="PDF has 0 pages with text (may be scanned images or empty).",
                )

            logger.info(
                "Extracted text from PDF file | filename=%s | pages=%d | chars=%d",
                filename,
                len(reader.pages),
                len(full_text),
            )
            return full_text, blocks
        except EmptyDocumentError:
            raise
        except Exception as exc:
            raise DocumentExtractionError(
                f"Failed to extract text from PDF '{filename}': {exc}",
                detail=f"PDF parsing error in '{filename}': {exc}",
            ) from exc

    def _extract_docx(self, content_bytes: bytes, filename: str) -> tuple[str, list[tuple[str, Optional[int]]]]:
        try:
            doc = docx.Document(io.BytesIO(content_bytes))
            paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
            full_text = "\n\n".join(paragraphs)

            if not full_text.strip():
                raise EmptyDocumentError(
                    f"DOCX file '{filename}' contains no extractable text.",
                    detail=f"Extracted content from DOCX '{filename}' is empty.",
                )

            logger.info(
                "Extracted text from DOCX file | filename=%s | paragraphs=%d | chars=%d",
                filename,
                len(paragraphs),
                len(full_text),
            )
            return full_text, [(full_text, None)]
        except EmptyDocumentError:
            raise
        except Exception as exc:
            raise DocumentExtractionError(
                f"Failed to extract text from DOCX '{filename}': {exc}",
                detail=f"DOCX parsing error in '{filename}': {exc}",
            ) from exc
