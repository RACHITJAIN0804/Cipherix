"""
services/embedding_service.py
------------------------------
Local text embedding generation service for Cipherix.

Provides a clean interface for embedding text chunks using local
Sentence Transformers models without sending data to external APIs.
"""

from typing import Optional
import numpy as np

from app.core.config import settings
from app.core.exceptions import DocumentProcessingError
from app.core.logger import get_logger

logger = get_logger(__name__)

# Module-level cache for loaded SentenceTransformer instance
_model_instance = None
_loaded_model_name: Optional[str] = None


def get_embedding_model(model_name: str | None = None):
    """
    Lazy-loads and caches the SentenceTransformer model.

    Parameters
    ----------
    model_name:
        Model identifier string. Defaults to `settings.embedding_model_name`.

    Returns
    -------
    SentenceTransformer:
        Loaded sentence transformer model instance.
    """
    global _model_instance, _loaded_model_name

    target_name = model_name or settings.embedding_model_name

    if _model_instance is not None and _loaded_model_name == target_name:
        return _model_instance

    try:
        from sentence_transformers import SentenceTransformer

        logger.info("Loading local embedding model | model_name=%s", target_name)
        _model_instance = SentenceTransformer(target_name)
        _loaded_model_name = target_name
        logger.info("Local embedding model loaded successfully | model_name=%s", target_name)
        return _model_instance
    except Exception as exc:
        logger.error("Failed to load embedding model | model_name=%s | error=%s", target_name, exc)
        raise DocumentProcessingError(
            f"Failed to load embedding model '{target_name}': {exc}",
            detail=str(exc),
        ) from exc


class EmbeddingService:
    """
    Service for generating text embeddings using local Sentence Transformers.
    """

    def __init__(self, model_name: str | None = None, batch_size: int | None = None) -> None:
        self.model_name: str = model_name or settings.embedding_model_name
        self.batch_size: int = batch_size or settings.embedding_batch_size

    def generate_embedding(self, text: str) -> list[float]:
        """
        Generate embedding vector for a single text string.

        Parameters
        ----------
        text:
            Input text snippet to embed.

        Returns
        -------
        list[float]:
            1D vector representation (e.g. 384 floats for all-MiniLM-L6-v2).
        """
        if not text or not text.strip():
            # Return dummy zero vector with standard dimension if text is empty
            model = get_embedding_model(self.model_name)
            dim = getattr(model, "get_embedding_dimension", model.get_sentence_embedding_dimension)()
            return [0.0] * dim

        results = self.generate_embeddings([text])
        return results[0]

    def generate_embeddings(self, texts: list[str]) -> list[list[float]]:
        """
        Generate embedding vectors for a list of text strings in efficient batches.

        Parameters
        ----------
        texts:
            List of input text strings.

        Returns
        -------
        list[list[float]]:
            List of vector float arrays corresponding to input texts.
        """
        if not texts:
            return []

        model = get_embedding_model(self.model_name)
        dim = getattr(model, "get_embedding_dimension", model.get_sentence_embedding_dimension)()

        # Handle empty/whitespace strings safely by replacing with space placeholder during encoding,
        # then zeroing out vector if needed.
        processed_inputs = [t.strip() if t and t.strip() else " " for t in texts]

        try:
            raw_embeddings = model.encode(
                processed_inputs,
                batch_size=self.batch_size,
                show_progress_bar=False,
                convert_to_numpy=True,
                normalize_embeddings=True,
            )

            results: list[list[float]] = []
            for original_text, emb in zip(texts, raw_embeddings):
                if not original_text or not original_text.strip():
                    results.append([0.0] * dim)
                else:
                    results.append(emb.tolist())

            logger.info(
                "Generated embeddings batch | count=%d | model=%s | batch_size=%d",
                len(texts),
                self.model_name,
                self.batch_size,
            )
            return results

        except Exception as exc:
            logger.error("Embedding generation failed | count=%d | error=%s", len(texts), exc)
            raise DocumentProcessingError(
                f"Embedding generation failed for batch of {len(texts)} item(s): {exc}",
                detail=str(exc),
            ) from exc

    def get_embedding_dimension(self) -> int:
        """Return the vector dimension of the loaded embedding model."""
        model = get_embedding_model(self.model_name)
        return getattr(model, "get_embedding_dimension", model.get_sentence_embedding_dimension)()
