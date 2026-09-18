"""
tests/test_step10_end_to_end_verification.py
----------------------------------------------
Step 10 End-to-End Verification Test Script for Cipherix Blockchain Integration.

Executes TESTS 1 - 13:
1. Register/login user.
2. Create a vault.
3. Upload a document.
4. Confirm document is encrypted and stored normally.
5. Confirm SHA-256 hash is generated.
6. Confirm hash is recorded on local blockchain.
7. Confirm blockchain transaction information is stored in database.
8. Run "Verify Integrity".
9. Confirm calculated hash matches blockchain hash & verification succeeds.
10. Modify/corrupt stored encrypted document in controlled test environment.
11. Run verification again and confirm hash mismatch is detected.
12. Confirm mismatch is recorded in Activity/Audit system.
13. Restore test document and verify successful integrity again.
"""

import io
import json
import uuid

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.database import get_db
from app.database.models import Base, BlockchainAnchorRecord, ComputerAccessAuditLog, Document as DocumentRecord
from app.main import create_app
from app.services.blockchain import BlockchainService, LocalBlockchainAdapter


@pytest.fixture(scope="function")
def in_memory_engine(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "VAULT_DIR", tmp_path / "vaults")
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
def local_adapter():
    return LocalBlockchainAdapter(network="local-development")


@pytest.fixture(scope="function")
def client(db_session: Session, local_adapter: LocalBlockchainAdapter, monkeypatch):
    from app.core.rate_limiter import _limiter
    _limiter.clear()
    monkeypatch.setattr(settings, "blockchain_enabled", True)
    import app.api.routes.blockchain as bc_route
    bc_route._blockchain_service = BlockchainService(adapter=local_adapter)
    app = create_app()

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def test_step10_end_to_end_flow(client: TestClient, db_session: Session):
    # TEST 1: Register/login user.
    username = f"step10_user_{uuid.uuid4().hex[:6]}"
    password = "SecurePassword123!"
    reg = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    assert reg.status_code == status.HTTP_201_CREATED, "TEST 1 Failed: Registration"
    user_id = reg.json()["id"]

    login = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert login.status_code == status.HTTP_200_OK, "TEST 1 Failed: Login"
    token = login.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # TEST 2: Create a vault.
    vault_name = "E2E Test Vault"
    vault_pass = "VaultPass123!"
    v_resp = client.post(
        "/api/v1/vaults/",
        headers=auth_headers,
        json={"name": vault_name, "password": vault_pass},
    )
    assert v_resp.status_code == status.HTTP_201_CREATED, "TEST 2 Failed: Vault creation"
    vault_id = v_resp.json()["vault_id"]

    unlock_resp = client.post(
        f"/api/v1/vaults/{vault_id}/unlock",
        headers=auth_headers,
        json={"password": vault_pass},
    )
    assert unlock_resp.status_code == status.HTTP_200_OK, "TEST 2 Failed: Vault unlock"

    # TEST 3: Upload a document.
    original_content = b"Confidential Financial Audit Report - Step 10 E2E Verification Document Data"
    files = {"file": ("audit_report.pdf", io.BytesIO(original_content), "application/pdf")}
    up_resp = client.post(
        f"/api/v1/vaults/{vault_id}/documents",
        headers={**auth_headers, "X-Vault-Password": vault_pass},
        files=files,
    )
    assert up_resp.status_code == status.HTTP_201_CREATED, "TEST 3 Failed: Document upload"
    doc_id = up_resp.json()["document_id"]

    # TEST 4: Confirm document is encrypted and stored normally.
    blob_path = settings.VAULT_DIR / vault_id / "encrypted" / f"{doc_id}.bin"
    assert blob_path.is_file(), "TEST 4 Failed: Encrypted blob missing on disk"
    ciphertext = blob_path.read_bytes()
    assert ciphertext != original_content, "TEST 4 Failed: Blob is not encrypted"

    # TEST 5: Confirm SHA-256 hash is generated.
    doc_rec = db_session.get(DocumentRecord, doc_id)
    assert doc_rec is not None, "TEST 5 Failed: Document record missing in DB"
    assert doc_rec.integrity_hash is not None and len(doc_rec.integrity_hash) == 64, "TEST 5 Failed: Invalid SHA-256 hash"

    # TEST 6 & 7: Confirm hash recorded on local blockchain & transaction info stored in DB.
    anchor_rec = (
        db_session.query(BlockchainAnchorRecord)
        .filter(BlockchainAnchorRecord.document_id == doc_id)
        .first()
    )
    assert anchor_rec is not None, "TEST 6 Failed: Missing anchor record"
    assert anchor_rec.tx_hash.startswith("0x"), "TEST 7 Failed: Missing tx_hash"
    assert anchor_rec.block_number > 0, "TEST 7 Failed: Missing block_number"
    assert anchor_rec.integrity_hash == doc_rec.integrity_hash, "TEST 6 Failed: Hash mismatch"

    # TEST 8 & 9: Run "Verify Integrity" & confirm calculated hash matches blockchain hash & verification succeeds.
    ver_resp = client.post(
        "/api/v1/blockchain/verify",
        headers=auth_headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert ver_resp.status_code == status.HTTP_200_OK, "TEST 8 Failed: Verification API call"
    ver_data = ver_resp.json()
    assert ver_data["verified"] is True, "TEST 9 Failed: Verification result false"
    assert ver_data["integrity_match"] is True, "TEST 9 Failed: Integrity match false"
    assert ver_data["blockchain_match"] is True, "TEST 9 Failed: Blockchain match false"

    # TEST 10: Modify/corrupt stored encrypted document in controlled test environment.
    tampered_bytes = b"TAMPERED_CIPHERTEXT_HEADER_AND_BODY_DATA"
    blob_path.write_bytes(tampered_bytes)

    # TEST 11: Run verification again and confirm hash mismatch is detected.
    ver_resp_tampered = client.post(
        "/api/v1/blockchain/verify",
        headers=auth_headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert ver_resp_tampered.status_code == status.HTTP_200_OK, "TEST 11 Failed: API call failed"
    tampered_data = ver_resp_tampered.json()
    assert tampered_data["verified"] is False, "TEST 11 Failed: Mismatch not detected"
    assert tampered_data["blockchain_match"] is False, "TEST 11 Failed: Blockchain match true on tampered file"

    # TEST 12: Confirm mismatch is recorded in Activity/Audit system.
    audit_logs = db_session.scalars(
        select(ComputerAccessAuditLog).where(
            ComputerAccessAuditLog.user_id == user_id,
            ComputerAccessAuditLog.action == "blockchain_verify_mismatch",
        )
    ).all()
    assert len(audit_logs) >= 1, "TEST 12 Failed: Mismatch audit event missing"
    assert audit_logs[0].result_status == "FAILED"

    # TEST 13: Restore test document and verify successful integrity again.
    blob_path.write_bytes(ciphertext)
    ver_resp_restored = client.post(
        "/api/v1/blockchain/verify",
        headers=auth_headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert ver_resp_restored.status_code == status.HTTP_200_OK, "TEST 13 Failed: API call failed"
    restored_data = ver_resp_restored.json()
    assert restored_data["verified"] is True, "TEST 13 Failed: Verification failed after restore"
    assert restored_data["blockchain_match"] is True, "TEST 13 Failed: Blockchain match failed after restore"
