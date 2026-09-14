
from typing import Optional
import numpy as np

from app.core.config import settings
from app.core.exceptions import DocumentProcessingError
from app.core.logger import get_logger

logger = get_logger(__name__)


_model_instance = None
_loaded_model_name: Optional[str] = None


def get_embedding_model(model_name: str | None = None):
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

    def __init__(self, model_name: str | None = None, batch_size: int | None = None) -> None:
        self.model_name: str = model_name or settings.embedding_model_name
        self.batch_size: int = batch_size or settings.embedding_batch_size

    def generate_embedding(self, text: str) -> list[float]:
        if not text or not text.strip():

            model = get_embedding_model(self.model_name)
            dim = getattr(model, "get_embedding_dimension", model.get_sentence_embedding_dimension)()
            return [0.0] * dim

        results = self.generate_embeddings([text])
        return results[0]

    def generate_embeddings(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []

        model = get_embedding_model(self.model_name)
        dim = getattr(model, "get_embedding_dimension", model.get_sentence_embedding_dimension)()


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
        model = get_embedding_model(self.model_name)
        return getattr(model, "get_embedding_dimension", model.get_sentence_embedding_dimension)()
