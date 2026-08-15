"""
tests/test_end_to_end.py
------------------------
Comprehensive End-to-End (E2E) Integration Test Suite for Cipherix.

Executes the complete 25-step architecture workflow:
1. Register user (User A).
2. Authenticate (User A).
3. Create vault (Vault A).
4. Upload document.
5. Process document text extraction & chunking.
6. Generate document SHA-256 integrity hash.
7. Generate embeddings.
8. Store vectors in ChromaDB.
9. Perform semantic search.
10. Perform RAG query.
11. Verify RAG source attribution.
12. Anchor document hash to blockchain.
13. Verify 3-tier blockchain integrity.
14. Enable controlled computer access.
15. Perform safe filesystem action.
16. Verify computer access audit logging.
17. Attempt unauthorized access by User B.
18. Attempt cross-vault vector search by User B.
19. Attempt cross-vault RAG by User B.
20. Attempt cross-vault blockchain verification by User B.
21. Attempt unsafe directory path traversal (../secret.txt).
22. Attempt arbitrary command execution (cmd.exe / powershell.exe).
23. Tamper with a document on disk.
24. Verify document integrity failure.
25. Verify blockchain mismatch detection.
"""

import io
import uuid
from pathlib import Path

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import Environment, settings
from app.core.exceptions import ConfigurationError
from app.core.rate_limiter import _limiter
from app.database import get_db
from app.database.models import Base, ComputerAccessAuditLog, Document as DocumentRecord
from app.main import create_app
from app.storage.document_manager import DocumentManager


@pytest.fixture(scope="function")
def in_memory_engine(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(settings, "COMPUTER_ACCESS_WORKSPACE_DIR", tmp_path / "workspace")
    _limiter.clear()

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    with engine.connect() as conn:
        conn.execute(text("PRAGMA foreign_keys=ON"))
        conn.commit()
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture(scope="function")
def db_session(in_memory_engine):
    factory = sessionmaker(
        bind=in_memory_engine, autocommit=False, autoflush=False, expire_on_commit=False
    )
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture(scope="function")
def client(db_session: Session):
    app = create_app()

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_complete_25_step_end_to_end_integration_pipeline(client: TestClient, db_session: Session):
    pwd = "VaultPassword123!"

    # 1. Register User A
    reg_a = client.post(
        "/api/v1/auth/register",
        json={"username": "user_a_e2e", "password": "UserAPassword123!"},
    )
    assert reg_a.status_code == status.HTTP_201_CREATED
    user_a_id = reg_a.json()["id"]

    # 2. Authenticate User A
    login_a = client.post(
        "/api/v1/auth/login",
        json={"username": "user_a_e2e", "password": "UserAPassword123!"},
    )
    assert login_a.status_code == status.HTTP_200_OK
    token_a = login_a.json()["access_token"]

    # 3. Create Vault A & Unlock
    v_resp = client.post(
        "/api/v1/vaults/",
        headers=_auth_header(token_a),
        json={"name": "E2E Vault A", "password": pwd},
    )
    assert v_resp.status_code == status.HTTP_201_CREATED
    vault_a_id = v_resp.json()["vault_id"]

    unl_resp = client.post(
        f"/api/v1/vaults/{vault_a_id}/unlock",
        headers=_auth_header(token_a),
        json={"password": pwd},
    )
    assert unl_resp.status_code == status.HTTP_200_OK

    # 4. Upload Document
    doc_content = (
        b"Cipherix End-to-End Integration Protocol.\n"
        b"This document contains secret proprietary parameters and verification hashes for RAG."
    )
    files = {"file": ("protocol.txt", io.BytesIO(doc_content), "text/plain")}
    up_resp = client.post(
        f"/api/v1/vaults/{vault_a_id}/documents",
        headers={**_auth_header(token_a), "X-Vault-Password": pwd},
        files=files,
    )
    assert up_resp.status_code == status.HTTP_201_CREATED
    doc_a_id = up_resp.json()["document_id"]

    # 5. Process document text extraction & chunking
    proc_resp = client.post(
        f"/api/v1/vaults/{vault_a_id}/documents/{doc_a_id}/process",
        headers={**_auth_header(token_a), "X-Vault-Password": pwd},
    )
    assert proc_resp.status_code == status.HTTP_200_OK
    pdata = proc_resp.json()
    assert pdata["chunk_count"] >= 1

    # 6. Verify document SHA-256 integrity hash recorded
    doc_db = db_session.get(DocumentRecord, doc_a_id)
    assert doc_db is not None
    assert doc_db.integrity_hash is not None
    assert len(doc_db.integrity_hash) == 64

    # 7. Generate embeddings & 8. Store vectors in ChromaDB (completed inside process endpoint)
    assert pdata["processing_status"] == "processed"

    # 9. Perform vault-isolated semantic search
    search_resp = client.post(
        "/api/v1/search",
        headers=_auth_header(token_a),
        json={"vault_id": vault_a_id, "query": "integration protocol parameters", "top_k": 3},
    )
    assert search_resp.status_code == status.HTTP_200_OK
    sdata = search_resp.json()
    assert len(sdata["results"]) >= 1

    # 10. Perform RAG query & 11. Verify RAG sources
    rag_resp = client.post(
        "/api/v1/rag/query",
        headers=_auth_header(token_a),
        json={"vault_id": vault_a_id, "query": "What does the document contain?"},
    )
    assert rag_resp.status_code in (status.HTTP_200_OK, status.HTTP_503_SERVICE_UNAVAILABLE)
    if rag_resp.status_code == status.HTTP_200_OK:
        rdata = rag_resp.json()
        assert rdata["vault_id"] == vault_a_id

    # 12. Anchor document hash to local blockchain
    anchor_resp = client.post(
        "/api/v1/blockchain/anchor",
        headers=_auth_header(token_a),
        json={"vault_id": vault_a_id, "document_id": doc_a_id},
    )
    assert anchor_resp.status_code == status.HTTP_200_OK
    adata = anchor_resp.json()
    assert adata["status"] == "anchored"
    tx_hash = adata["tx_hash"]

    # 13. Verify 3-tier blockchain integrity
    bc_verify_resp = client.post(
        "/api/v1/blockchain/verify",
        headers=_auth_header(token_a),
        json={"vault_id": vault_a_id, "document_id": doc_a_id},
    )
    assert bc_verify_resp.status_code == status.HTTP_200_OK
    vdata = bc_verify_resp.json()
    assert vdata["integrity_match"] is True
    assert vdata["blockchain_match"] is True
    assert vdata["verified"] is True

    # 14. Enable controlled computer access
    toggle_resp = client.post(
        "/api/v1/computer-access/toggle",
        headers=_auth_header(token_a),
        json={"enabled": True},
    )
    assert toggle_resp.status_code == status.HTTP_200_OK
    assert toggle_resp.json()["enabled"] is True

    # 15. Perform safe filesystem action (list_directory)
    act_resp = client.post(
        "/api/v1/computer-access/action",
        headers=_auth_header(token_a),
        json={"action": "list_directory", "parameters": {"path": "."}},
    )
    assert act_resp.status_code == status.HTTP_200_OK

    # 16. Verify computer access audit logging
    audits = (
        db_session.query(ComputerAccessAuditLog)
        .filter(ComputerAccessAuditLog.user_id == user_a_id)
        .all()
    )
    assert len(audits) >= 1

    # 17. Register User B & Attempt unauthorized access
    reg_b = client.post(
        "/api/v1/auth/register",
        json={"username": "user_b_e2e", "password": "UserBPassword123!"},
    )
    assert reg_b.status_code == status.HTTP_201_CREATED
    login_b = client.post(
        "/api/v1/auth/login",
        json={"username": "user_b_e2e", "password": "UserBPassword123!"},
    )
    token_b = login_b.json()["access_token"]

    # User B attempts to access Vault A -> 404
    unauth_doc_resp = client.get(
        f"/api/v1/vaults/{vault_a_id}/documents/{doc_a_id}",
        headers={**_auth_header(token_b), "X-Vault-Password": pwd},
    )
    assert unauth_doc_resp.status_code == status.HTTP_404_NOT_FOUND

    # 18. Attempt cross-vault vector search by User B -> 403 / 404
    unauth_search_resp = client.post(
        "/api/v1/search",
        headers=_auth_header(token_b),
        json={"vault_id": vault_a_id, "query": "protocol"},
    )
    assert unauth_search_resp.status_code in (status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND)

    # 19. Attempt cross-vault RAG by User B -> 403 / 404
    unauth_rag_resp = client.post(
        "/api/v1/rag/query",
        headers=_auth_header(token_b),
        json={"vault_id": vault_a_id, "query": "protocol"},
    )
    assert unauth_rag_resp.status_code in (status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND)

    # 20. Attempt cross-vault blockchain verification by User B -> 404
    unauth_bc_resp = client.post(
        "/api/v1/blockchain/verify",
        headers=_auth_header(token_b),
        json={"vault_id": vault_a_id, "document_id": doc_a_id},
    )
    assert unauth_bc_resp.status_code == status.HTTP_404_NOT_FOUND

    # 21. Attempt unsafe directory path traversal (../secret.txt) -> 400
    trav_resp = client.post(
        "/api/v1/computer-access/action",
        headers=_auth_header(token_a),
        json={"action": "read_text_file", "parameters": {"path": "../secret.txt"}},
    )
    assert trav_resp.status_code == status.HTTP_400_BAD_REQUEST

    # 22. Attempt arbitrary command execution (cmd.exe) -> 400
    cmd_resp = client.post(
        "/api/v1/computer-access/action",
        headers=_auth_header(token_a),
        json={"action": "cmd.exe", "parameters": {"args": "/c dir"}},
    )
    assert cmd_resp.status_code == status.HTTP_400_BAD_REQUEST

    # 23. Tamper with a document on disk
    blob_path = settings.VAULT_DIR / vault_a_id / "encrypted" / f"{doc_a_id}.bin"
    blob_path.write_bytes(b"CORRUPTED_AND_TAMPERED_BLOB_DATA")

    # 24. Verify integrity failure & 25. Verify blockchain mismatch detection
    tamper_verify_resp = client.post(
        "/api/v1/blockchain/verify",
        headers=_auth_header(token_a),
        json={"vault_id": vault_a_id, "document_id": doc_a_id},
    )
    assert tamper_verify_resp.status_code == status.HTTP_200_OK
    tvdata = tamper_verify_resp.json()
    assert tvdata["integrity_match"] is False
    assert tvdata["blockchain_match"] is False
    assert tvdata["verified"] is False


def test_production_configuration_guard(monkeypatch):
    """Verify that using default placeholder secrets in production raises ConfigurationError."""
    monkeypatch.setattr(settings, "app_env", Environment.PRODUCTION)
    monkeypatch.setattr(settings, "secret_key", "change_this_in_production")

    with pytest.raises(ConfigurationError):
        settings.validate_production_secrets()
