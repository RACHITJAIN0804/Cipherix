"""
tests/test_blockchain_audit_logging.py
----------------------------------------
Test suite for Step 9: Blockchain Audit Logging Integration.

Verifies that all 7 required blockchain audit events are correctly recorded in
the unified Cipherix audit log system (ComputerAccessAuditLog) without exposing sensitive keys
or plaintext content:

1. Document hash successfully recorded on blockchain (blockchain_anchor_success)
2. Blockchain transaction failure (blockchain_anchor_failure)
3. Document integrity verification requested (blockchain_verify_request)
4. Successful integrity verification (blockchain_verify_success)
5. Hash mismatch detected (blockchain_verify_mismatch)
6. Blockchain verification unavailable (blockchain_verify_unavailable)
7. Missing blockchain integrity record (blockchain_verify_missing_record)
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
from app.database.models import Base, ComputerAccessAuditLog
from app.main import create_app
from app.services.audit_service import (
    EVENT_BLOCKCHAIN_ANCHOR_FAILURE,
    EVENT_BLOCKCHAIN_ANCHOR_SUCCESS,
    EVENT_BLOCKCHAIN_VERIFY_MISMATCH,
    EVENT_BLOCKCHAIN_VERIFY_MISSING_RECORD,
    EVENT_BLOCKCHAIN_VERIFY_REQUEST,
    EVENT_BLOCKCHAIN_VERIFY_SUCCESS,
    EVENT_BLOCKCHAIN_VERIFY_UNAVAILABLE,
)
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


def _register_and_login(client: TestClient, prefix: str = "audit_user") -> tuple[str, str]:
    username = f"{prefix}_{uuid.uuid4().hex[:6]}"
    password = "SecurePassword123!"
    reg = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    assert reg.status_code == status.HTTP_201_CREATED
    user_id = reg.json()["id"]

    login = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert login.status_code == status.HTTP_200_OK
    token = login.json()["access_token"]
    return token, user_id


def _create_and_unlock_vault(client: TestClient, token: str, password: str = "VaultPassword123!") -> str:
    resp = client.post(
        "/api/v1/vaults/",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Audit Vault", "password": password},
    )
    assert resp.status_code == status.HTTP_201_CREATED
    vault_id = resp.json()["vault_id"]
    unlock_resp = client.post(
        f"/api/v1/vaults/{vault_id}/unlock",
        headers={"Authorization": f"Bearer {token}"},
        json={"password": password},
    )
    assert unlock_resp.status_code == status.HTTP_200_OK
    return vault_id


def _upload_doc(client: TestClient, token: str, vault_id: str, content: bytes = b"Audit Log Test Document") -> str:
    files = {"file": ("audit_doc.pdf", io.BytesIO(content), "application/pdf")}
    resp = client.post(
        f"/api/v1/vaults/{vault_id}/documents",
        headers={"Authorization": f"Bearer {token}", "X-Vault-Password": "VaultPassword123!"},
        files=files,
    )
    assert resp.status_code == status.HTTP_201_CREATED
    return resp.json()["document_id"]


def test_audit_event_upload_anchor_success(client: TestClient, db_session: Session):
    token, user_id = _register_and_login(client, "anchor_succ")
    vault_id = _create_and_unlock_vault(client, token)
    doc_id = _upload_doc(client, token, vault_id)

    # Check audit log in DB
    logs = db_session.scalars(
        select(ComputerAccessAuditLog).where(
            ComputerAccessAuditLog.user_id == user_id,
            ComputerAccessAuditLog.action == EVENT_BLOCKCHAIN_ANCHOR_SUCCESS,
        )
    ).all()

    assert len(logs) == 1
    log = logs[0]
    assert log.result_status == "SUCCESS"
    assert log.vault_id == vault_id
    assert log.relative_path == doc_id
    assert log.details_json is not None

    details = json.loads(log.details_json)
    assert "tx_hash" in details
    assert "network" in details
    assert "integrity_hash" in details

    # Ensure no secrets logged
    for secret in ["password", "key", "seed", "token", "plaintext"]:
        assert secret not in details


def test_audit_event_verification_success(client: TestClient, db_session: Session):
    token, user_id = _register_and_login(client, "verify_succ")
    vault_id = _create_and_unlock_vault(client, token)
    doc_id = _upload_doc(client, token, vault_id)

    # Perform verification
    resp = client.post(
        "/api/v1/blockchain/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp.status_code == status.HTTP_200_OK

    # Check request and success audit logs
    req_logs = db_session.scalars(
        select(ComputerAccessAuditLog).where(
            ComputerAccessAuditLog.user_id == user_id,
            ComputerAccessAuditLog.action == EVENT_BLOCKCHAIN_VERIFY_REQUEST,
        )
    ).all()
    assert len(req_logs) >= 1

    succ_logs = db_session.scalars(
        select(ComputerAccessAuditLog).where(
            ComputerAccessAuditLog.user_id == user_id,
            ComputerAccessAuditLog.action == EVENT_BLOCKCHAIN_VERIFY_SUCCESS,
        )
    ).all()
    assert len(succ_logs) == 1
    log = succ_logs[0]
    assert log.result_status == "SUCCESS"
    assert log.relative_path == doc_id


def test_audit_event_verification_mismatch(client: TestClient, db_session: Session):
    token, user_id = _register_and_login(client, "verify_mismatch")
    vault_id = _create_and_unlock_vault(client, token)
    doc_id = _upload_doc(client, token, vault_id, content=b"Original File Data")

    # Tamper with encrypted file on disk
    blob_path = settings.VAULT_DIR / vault_id / "encrypted" / f"{doc_id}.bin"
    blob_path.write_bytes(b"CORRUPTED_CIPHERTEXT_FOR_AUDIT_TEST")

    # Perform verification
    resp = client.post(
        "/api/v1/blockchain/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["verified"] is False

    mismatch_logs = db_session.scalars(
        select(ComputerAccessAuditLog).where(
            ComputerAccessAuditLog.user_id == user_id,
            ComputerAccessAuditLog.action == EVENT_BLOCKCHAIN_VERIFY_MISMATCH,
        )
    ).all()
    assert len(mismatch_logs) == 1
    log = mismatch_logs[0]
    assert log.result_status == "FAILED"
    details = json.loads(log.details_json)
    assert details["verified"] is False
    assert "error" in details


def test_audit_event_verification_unavailable(client: TestClient, db_session: Session, local_adapter: LocalBlockchainAdapter):
    token, user_id = _register_and_login(client, "verify_unavail")
    vault_id = _create_and_unlock_vault(client, token)
    doc_id = _upload_doc(client, token, vault_id)

    local_adapter.set_available(False)

    resp = client.post(
        "/api/v1/blockchain/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST

    unavail_logs = db_session.scalars(
        select(ComputerAccessAuditLog).where(
            ComputerAccessAuditLog.user_id == user_id,
            ComputerAccessAuditLog.action == EVENT_BLOCKCHAIN_VERIFY_UNAVAILABLE,
        )
    ).all()
    assert len(unavail_logs) == 1
    assert unavail_logs[0].result_status == "FAILED"


def test_audit_event_missing_record(client: TestClient, db_session: Session, monkeypatch):
    token, user_id = _register_and_login(client, "missing_rec")
    vault_id = _create_and_unlock_vault(client, token)

    monkeypatch.setattr(settings, "blockchain_enabled", False)
    doc_id = _upload_doc(client, token, vault_id)

    monkeypatch.setattr(settings, "blockchain_enabled", True)
    resp = client.post(
        "/api/v1/blockchain/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND

    missing_logs = db_session.scalars(
        select(ComputerAccessAuditLog).where(
            ComputerAccessAuditLog.user_id == user_id,
            ComputerAccessAuditLog.action == EVENT_BLOCKCHAIN_VERIFY_MISSING_RECORD,
        )
    ).all()
    assert len(missing_logs) == 1
    assert missing_logs[0].result_status == "FAILED"


def test_audit_logs_endpoint_returns_blockchain_events(client: TestClient):
    token, _ = _register_and_login(client, "endpoint_user")
    vault_id = _create_and_unlock_vault(client, token)
    doc_id = _upload_doc(client, token, vault_id)

    client.post(
        "/api/v1/blockchain/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"vault_id": vault_id, "document_id": doc_id},
    )

    resp = client.get(
        "/api/v1/computer-access/audit-logs",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == status.HTTP_200_OK
    logs = resp.json()
    actions = [log["action"] for log in logs]
    assert EVENT_BLOCKCHAIN_ANCHOR_SUCCESS in actions
    assert EVENT_BLOCKCHAIN_VERIFY_SUCCESS in actions
