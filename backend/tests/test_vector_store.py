"""
tests/test_vector_store.py
---------------------------
Tests for VectorStore component and ChromaDB vector isolation.
"""

import pytest
from unittest.mock import MagicMock, patch

from app.core.exceptions import DocumentProcessingError
from app.services.document_processing.chunker import DocumentChunk
from app.services.vector_store import VectorStore


@pytest.fixture
def temp_vector_store(tmp_path):
    return VectorStore(db_dir=tmp_path / "test_vector_db")


def test_vector_store_add_and_search(temp_vector_store):
    vault_id = "v-11111111-1111-1111-1111-111111111111"
    doc_id = "d-11111111-1111-1111-1111-111111111111"

    chunk = DocumentChunk(
        chunk_id="chunk-1",
        document_id=doc_id,
        chunk_index=0,
        character_count=25,
        page_number=1,
        text="Sample text content for vector store test.",
    )
    fake_embedding = [0.1] * 384

    temp_vector_store.add_chunks(
        chunks=[chunk],
        embeddings=[fake_embedding],
        vault_id=vault_id,
        document_id=doc_id,
    )

    results = temp_vector_store.search_vault(
        query_embedding=fake_embedding,
        vault_id=vault_id,
        top_k=5,
    )

    assert len(results) == 1
    assert results[0]["chunk_id"] == "chunk-1"
    assert results[0]["document_id"] == doc_id
    assert results[0]["vault_id"] == vault_id
    assert results[0]["text"] == "Sample text content for vector store test."
    assert results[0]["page_number"] == 1


def test_vector_store_reindexing_prevents_duplicates(temp_vector_store):
    vault_id = "v-22222222-2222-2222-2222-222222222222"
    doc_id = "d-22222222-2222-2222-2222-222222222222"

    chunk_v1 = DocumentChunk(
        chunk_id="chunk-v1",
        document_id=doc_id,
        chunk_index=0,
        character_count=15,
        page_number=None,
        text="Version 1 text.",
    )
    fake_embedding = [0.2] * 384

    # Index first time
    temp_vector_store.add_chunks(
        chunks=[chunk_v1],
        embeddings=[fake_embedding],
        vault_id=vault_id,
        document_id=doc_id,
    )

    # Re-index second time with updated chunk
    chunk_v2 = DocumentChunk(
        chunk_id="chunk-v2",
        document_id=doc_id,
        chunk_index=0,
        character_count=15,
        page_number=None,
        text="Version 2 text.",
    )
    temp_vector_store.add_chunks(
        chunks=[chunk_v2],
        embeddings=[fake_embedding],
        vault_id=vault_id,
        document_id=doc_id,
    )

    results = temp_vector_store.search_vault(
        query_embedding=fake_embedding,
        vault_id=vault_id,
        top_k=10,
    )

    assert len(results) == 1
    assert results[0]["chunk_id"] == "chunk-v2"
    assert results[0]["text"] == "Version 2 text."


def test_vector_store_delete_document_vectors(temp_vector_store):
    vault_id = "v-33333333-3333-3333-3333-333333333333"
    doc_id = "d-33333333-3333-3333-3333-333333333333"

    chunk = DocumentChunk(
        chunk_id="chunk-del",
        document_id=doc_id,
        chunk_index=0,
        character_count=10,
        page_number=None,
        text="To be deleted text.",
    )
    fake_emb = [0.3] * 384

    temp_vector_store.add_chunks(
        chunks=[chunk],
        embeddings=[fake_emb],
        vault_id=vault_id,
        document_id=doc_id,
    )

    temp_vector_store.delete_document_vectors(document_id=doc_id, vault_id=vault_id)

    results = temp_vector_store.search_vault(
        query_embedding=fake_emb,
        vault_id=vault_id,
        top_k=5,
    )
    assert len(results) == 0


def test_vector_store_delete_vault_vectors(temp_vector_store):
    vault_id = "v-44444444-4444-4444-4444-444444444444"
    doc1 = "d-41"
    doc2 = "d-42"

    c1 = DocumentChunk("c41", doc1, 0, 10, None, "Doc 1 text")
    c2 = DocumentChunk("c42", doc2, 0, 10, None, "Doc 2 text")
    fake_emb = [0.4] * 384

    temp_vector_store.add_chunks([c1], [fake_emb], vault_id, doc1)
    temp_vector_store.add_chunks([c2], [fake_emb], vault_id, doc2)

    temp_vector_store.delete_vault_vectors(vault_id)

    results = temp_vector_store.search_vault(fake_emb, vault_id)
    assert len(results) == 0


def test_vector_store_vault_isolation_search(temp_vector_store):
    v_a = "vault-user-a"
    v_b = "vault-user-b"
    d_a = "doc-a"
    d_b = "doc-b"

    c_a = DocumentChunk("c-a", d_a, 0, 20, None, "Secret user A document content")
    c_b = DocumentChunk("c-b", d_b, 0, 20, None, "Secret user B document content")
    emb = [0.5] * 384

    temp_vector_store.add_chunks([c_a], [emb], v_a, d_a)
    temp_vector_store.add_chunks([c_b], [emb], v_b, d_b)

    # Search vault A
    res_a = temp_vector_store.search_vault(emb, vault_id=v_a)
    assert len(res_a) == 1
    assert res_a[0]["vault_id"] == v_a
    assert res_a[0]["text"] == "Secret user A document content"

    # Search vault B
    res_b = temp_vector_store.search_vault(emb, vault_id=v_b)
    assert len(res_b) == 1
    assert res_b[0]["vault_id"] == v_b
    assert res_b[0]["text"] == "Secret user B document content"


def test_vector_store_failure_handling(temp_vector_store):
    with patch.object(temp_vector_store, "_get_collection", side_effect=Exception("DB breakdown")):
        with pytest.raises(DocumentProcessingError):
            temp_vector_store.add_chunks(
                chunks=[DocumentChunk("c", "d", 0, 5, None, "test")],
                embeddings=[[0.1] * 384],
                vault_id="v",
                document_id="d",
            )
