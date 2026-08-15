"""
tests/test_document_processing.py
-----------------------------------
Comprehensive test suite for Cipherix document processing foundation (RAG).
"""

import io
import pytest
import pypdf
import docx
from fastapi import status
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.exceptions import (
    EmptyDocumentError,
    UnsupportedFileTypeError,
)
from app.database import get_db
from app.main import create_app
from app.services.document_processing.chunker import TextChunker
from app.services.document_processing.cleaner import TextCleaner
from app.services.document_processing.extractor import DocumentExtractor


@pytest.fixture(scope="function")
def in_memory_engine(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "VAULT_DIR", tmp_path / "vaults")
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    from app.database.models import Base
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session(in_memory_engine):
    from sqlalchemy.orm import sessionmaker
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=in_memory_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def client(in_memory_engine, db_session):
    app = create_app()

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _register_and_login(client, username: str = "docuser", password: str = "Password123!") -> dict:
    client.post("/api/v1/auth/register", json={"username": username, "password": password})
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _create_synthetic_pdf(pages: list[str]) -> bytes:
    writer = pypdf.PdfWriter()
    for page_text in pages:
        writer.add_blank_page(width=612, height=792)
    stream = io.BytesIO()
    writer.write(stream)
    return stream.getvalue()


def _create_synthetic_docx(paragraphs: list[str]) -> bytes:
    doc = docx.Document()
    for p in paragraphs:
        doc.add_paragraph(p)
    stream = io.BytesIO()
    doc.save(stream)
    return stream.getvalue()


class TestExtractorCleanerChunkerUnit:
    def test_txt_extraction(self):
        extractor = DocumentExtractor()
        content = b"Header line\n\nParagraph content for testing."
        text, blocks = extractor.extract_text(content, "test.txt", "text/plain")
        assert "Header line" in text
        assert "Paragraph content" in text

    def test_pdf_extraction(self):
        writer = pypdf.PdfWriter()
        page = writer.add_blank_page(width=612, height=792)
        stream = io.BytesIO()
        writer.write(stream)
        pdf_bytes = stream.getvalue()

        extractor = DocumentExtractor()
        # Empty/blank page PDF will raise EmptyDocumentError or return text
        with pytest.raises(EmptyDocumentError):
            extractor.extract_text(pdf_bytes, "blank.pdf", "application/pdf")

    def test_docx_extraction(self):
        docx_bytes = _create_synthetic_docx(["First paragraph text.", "Second paragraph text."])
        extractor = DocumentExtractor()
        text, blocks = extractor.extract_text(docx_bytes, "test.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        assert "First paragraph text." in text
        assert "Second paragraph text." in text

    def test_unsupported_file_type(self):
        extractor = DocumentExtractor()
        with pytest.raises(UnsupportedFileTypeError):
            extractor.extract_text(b"some binary data", "image.png", "image/png")

    def test_empty_document(self):
        extractor = DocumentExtractor()
        with pytest.raises(EmptyDocumentError):
            extractor.extract_text(b"", "empty.txt", "text/plain")

    def test_text_cleaning(self):
        cleaner = TextCleaner()
        raw = "Line 1   with   spaces.\r\n\r\n\n\nLine 2 with \x00control chars.\x07"
        cleaned = cleaner.clean(raw)
        assert "\r" not in cleaned
        assert "\x00" not in cleaned
        assert "\x07" not in cleaned
        assert "Line 1 with spaces." in cleaned
        assert "\n\n" in cleaned
        assert "\n\n\n" not in cleaned

    def test_deterministic_chunking_overlap_ordering_and_no_text_loss(self):
        chunker = TextChunker(default_chunk_size=100, default_chunk_overlap=20)
        sample_text = (
            "Sentence one is simple. "
            "Sentence two contains important context. "
            "Sentence three expands further on the topic. "
            "Sentence four concludes the comprehensive overview document."
        )
        chunks1 = chunker.chunk_text(sample_text, "doc1", chunk_size=100, chunk_overlap=20)
        chunks2 = chunker.chunk_text(sample_text, "doc1", chunk_size=100, chunk_overlap=20)

        # Deterministic check
        assert len(chunks1) == len(chunks2)
        for c1, c2 in zip(chunks1, chunks2):
            assert c1.chunk_id == c2.chunk_id
            assert c1.text == c2.text
            assert c1.chunk_index == c2.chunk_index

        # Ordering check
        for i, c in enumerate(chunks1):
            assert c.chunk_index == i

        # Overlap check
        if len(chunks1) > 1:
            overlap_tail = chunks1[0].text[-10:]
            assert overlap_tail in chunks1[1].text or chunks1[1].text in chunks1[0].text

        # No text loss check
        combined = " ".join([c.text for c in chunks1])
        for word in ["Sentence", "simple", "important", "topic", "overview"]:
            assert word in combined


class TestDocumentProcessingPipelineIntegration:
    def test_pipeline_txt_pdf_docx_flow(self, client):
        password = "Password123!"
        headers = _register_and_login(client, "proc_user", password)

        # 1. Create vault
        v_res = client.post("/api/v1/vaults/", headers=headers, json={"name": "Proc Vault", "password": password})
        assert v_res.status_code == status.HTTP_201_CREATED
        v_id = v_res.json()["vault_id"]

        client.post(f"/api/v1/vaults/{v_id}/unlock", headers=headers)

        # Upload TXT
        txt_content = b"This is a comprehensive text document for RAG processing testing. It contains multiple sentences to test chunking."
        t_res = client.post(
            f"/api/v1/vaults/{v_id}/documents",
            headers={**headers, "X-Vault-Password": password},
            files={"file": ("sample.txt", io.BytesIO(txt_content), "text/plain")},
        )
        assert t_res.status_code == status.HTTP_201_CREATED
        t_doc_id = t_res.json()["document_id"]

        # Process TXT document
        p_res = client.post(
            f"/api/v1/vaults/{v_id}/documents/{t_doc_id}/process",
            headers={**headers, "X-Vault-Password": password},
        )
        assert p_res.status_code == status.HTTP_200_OK
        p_data = p_res.json()
        assert p_data["processing_status"] == "processed"
        assert p_data["chunk_count"] > 0
        assert len(p_data["chunks"]) == p_data["chunk_count"]
        assert p_data["chunks"][0]["document_id"] == t_doc_id

        # Upload DOCX
        docx_bytes = _create_synthetic_docx(["Sample docx paragraph for processing.", "Another docx paragraph."])
        d_res = client.post(
            f"/api/v1/vaults/{v_id}/documents",
            headers={**headers, "X-Vault-Password": password},
            files={"file": ("sample.docx", io.BytesIO(docx_bytes), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")},
        )
        assert d_res.status_code == status.HTTP_201_CREATED
        d_doc_id = d_res.json()["document_id"]

        dp_res = client.post(
            f"/api/v1/vaults/{v_id}/documents/{d_doc_id}/process",
            headers={**headers, "X-Vault-Password": password},
        )
        assert dp_res.status_code == status.HTTP_200_OK
        assert dp_res.json()["processing_status"] == "processed"

    def test_corrupted_encrypted_document_integrity_failure(self, client):
        password = "Password123!"
        headers = _register_and_login(client, "corrupt_user", password)

        v_res = client.post("/api/v1/vaults/", headers=headers, json={"name": "Corrupt Vault", "password": password})
        v_id = v_res.json()["vault_id"]
        client.post(f"/api/v1/vaults/{v_id}/unlock", headers=headers)

        doc_res = client.post(
            f"/api/v1/vaults/{v_id}/documents",
            headers={**headers, "X-Vault-Password": password},
            files={"file": ("corrupt.txt", io.BytesIO(b"Valid content initially"), "text/plain")},
        )
        doc_id = doc_res.json()["document_id"]

        # Tamper with the encrypted .bin file on disk
        blob_path = settings.VAULT_DIR / v_id / "encrypted" / f"{doc_id}.bin"
        blob_path.write_bytes(b"TAMPERED CIPHERTEXT CONTENT")

        # Processing must fail with 409 Conflict (Integrity error)
        p_res = client.post(
            f"/api/v1/vaults/{v_id}/documents/{doc_id}/process",
            headers={**headers, "X-Vault-Password": password},
        )
        assert p_res.status_code == status.HTTP_409_CONFLICT

    def test_unauthorized_document_processing_rejected(self, client):
        pass1 = "Password123!"
        headers1 = _register_and_login(client, "owner_user", pass1)
        headers2 = _register_and_login(client, "attacker_user", pass1)

        v_res = client.post("/api/v1/vaults/", headers=headers1, json={"name": "Private Vault", "password": pass1})
        v_id = v_res.json()["vault_id"]
        client.post(f"/api/v1/vaults/{v_id}/unlock", headers=headers1)

        doc_res = client.post(
            f"/api/v1/vaults/{v_id}/documents",
            headers={**headers1, "X-Vault-Password": pass1},
            files={"file": ("secret.txt", io.BytesIO(b"Secret content"), "text/plain")},
        )
        doc_id = doc_res.json()["document_id"]

        # User 2 attempts to process User 1's document
        p_res = client.post(
            f"/api/v1/vaults/{v_id}/documents/{doc_id}/process",
            headers={**headers2, "X-Vault-Password": pass1},
        )
        assert p_res.status_code in (status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND)
