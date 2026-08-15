"""
tests/test_embedding_service.py
--------------------------------
Tests for EmbeddingService component.
"""

import pytest
from unittest.mock import MagicMock, patch

from app.core.exceptions import DocumentProcessingError
from app.services.embedding_service import EmbeddingService, get_embedding_model


def test_embedding_service_single_generation():
    service = EmbeddingService()
    text = "Cipherix is a secure zero-knowledge encrypted vault application."
    vec = service.generate_embedding(text)

    assert isinstance(vec, list)
    assert len(vec) == 384
    assert all(isinstance(val, float) for val in vec)


def test_embedding_service_batch_generation():
    service = EmbeddingService()
    texts = [
        "First document paragraph.",
        "Second document paragraph with different words.",
        "Third paragraph describing encryption algorithms.",
    ]
    vecs = service.generate_embeddings(texts)

    assert len(vecs) == 3
    for v in vecs:
        assert len(v) == 384


def test_embedding_service_deterministic_output():
    service = EmbeddingService()
    text = "Deterministic vector text testing."
    vec1 = service.generate_embedding(text)
    vec2 = service.generate_embedding(text)

    assert vec1 == vec2


def test_embedding_service_empty_input_handling():
    service = EmbeddingService()
    empty_vec = service.generate_embedding("")
    assert len(empty_vec) == 384
    assert all(v == 0.0 for v in empty_vec)

    batch_vecs = service.generate_embeddings(["", "   ", "Valid text"])
    assert len(batch_vecs) == 3
    assert all(v == 0.0 for v in batch_vecs[0])
    assert all(v == 0.0 for v in batch_vecs[1])
    assert len(batch_vecs[2]) == 384


def test_embedding_service_model_load_failure():
    with patch("sentence_transformers.SentenceTransformer", side_effect=Exception("Model load error")):
        with pytest.raises(DocumentProcessingError) as exc_info:
            get_embedding_model("non_existent_invalid_model_12345")
        assert "Failed to load embedding model" in str(exc_info.value)
