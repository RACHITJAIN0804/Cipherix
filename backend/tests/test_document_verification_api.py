"""
tests/test_document_verification_api.py
----------------------------------------
Focused test suite for Step 7: Document Integrity Verification API.

Verifies:
1. Verification success test (hash match).
2. Hash mismatch test (detects tampered file on disk).
3. Unauthorized access test (cross-user/cross-vault access rejected with 404).
4. Missing blockchain record test (returns 404 when no anchor record exists).
5. Non-existent document test (returns 404).
6. Blockchain unavailable test (returns 400 when adapter is unavailable).
7. Verification GET endpoint (GET /api/v1/blockchain/verify/{document_id}).
"""

import io
import uuid

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.database import get_db
from app.database.models import Base, BlockchainAnchorRecord, Document as DocumentRecord, Vault as VaultRecord
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


def _register_and_login(client: TestClient, username_prefix: str = "ver_user") -> tuple[str, str]:
    username = f"{username_prefix}_{uuid.uuid4().hex[:6]}"
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
        json={"name": "Verify Vault", "password": password},
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


def _upload_doc(client: TestClient, token: str, vault_id: str, content: bytes = b"Legal Contract Text") -> str:
    files = {"file": ("contract.pdf", io.BytesIO(content), "application/pdf")}
    resp = client.post(
        f"/api/v1/vaults/{vault_id}/documents",
        headers={"Authorization": f"Bearer {token}", "X-Vault-Password": "VaultPassword123!"},
        files=files,
    )
    assert resp.status_code == status.HTTP_201_CREATED
    return resp.json()["document_id"]


def test_verification_success(client: TestClient):
    token, _ = _register_and_login(client, "ver_succ")
    vault_id = _create_and_unlock_vault(client, token)
    doc_id = _upload_doc(client, token, vault_id)

    resp = client.post(
        "/api/v1/blockchain/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert data["document_id"] == doc_id
    assert data["verified"] is True
    assert data["integrity_match"] is True
    assert data["blockchain_match"] is True
    assert data["stored_integrity_hash"] == data["current_integrity_hash"]
    assert data["current_integrity_hash"] == data["blockchain_hash"]
    assert data["tx_hash"].startswith("0x")
    assert data["message"] is not None
    assert "successfully verified" in data["message"].lower()


def test_verification_hash_mismatch(client: TestClient, db_session: Session):
    token, _ = _register_and_login(client, "ver_mismatch")
    vault_id = _create_and_unlock_vault(client, token)
    doc_id = _upload_doc(client, token, vault_id, content=b"Original Authentic Content")

    # Tamper with encrypted file on disk
    blob_path = settings.VAULT_DIR / vault_id / "encrypted" / f"{doc_id}.bin"
    blob_path.write_bytes(b"TAMPERED_CIPHERTEXT_FOR_STEP_7_TEST")

    resp = client.post(
        "/api/v1/blockchain/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert data["document_id"] == doc_id
    assert data["verified"] is False
    assert data["blockchain_match"] is False
    assert "mismatch" in data["message"].lower()


def test_verification_unauthorized_access(client: TestClient):
    token_owner, _ = _register_and_login(client, "owner_user")
    token_attacker, _ = _register_and_login(client, "attacker_user")

    vault_id = _create_and_unlock_vault(client, token_owner)
    doc_id = _upload_doc(client, token_owner, vault_id)

    # Attacker tries to verify owner's document -> 404
    resp = client.post(
        "/api/v1/blockchain/verify",
        headers={"Authorization": f"Bearer {token_attacker}"},
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_verification_missing_blockchain_record(client: TestClient, db_session: Session, monkeypatch):
    token, _ = _register_and_login(client, "no_anchor_user")
    vault_id = _create_and_unlock_vault(client, token)

    # Upload document while blockchain is disabled (no anchor created)
    monkeypatch.setattr(settings, "blockchain_enabled", False)
    doc_id = _upload_doc(client, token, vault_id)

    # Enable blockchain and attempt verification -> 404 Anchor Not Found
    monkeypatch.setattr(settings, "blockchain_enabled", True)
    resp = client.post(
        "/api/v1/blockchain/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND
    assert "no blockchain" in resp.json()["detail"].lower()


def test_verification_non_existent_document(client: TestClient):
    token, _ = _register_and_login(client, "nonexist_user")
    vault_id = _create_and_unlock_vault(client, token)
    fake_doc_id = str(uuid.uuid4())

    resp = client.post(
        "/api/v1/blockchain/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"vault_id": vault_id, "document_id": fake_doc_id},
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_verification_blockchain_unavailable(client: TestClient, local_adapter: LocalBlockchainAdapter):
    token, _ = _register_and_login(client, "unavail_user")
    vault_id = _create_and_unlock_vault(client, token)
    doc_id = _upload_doc(client, token, vault_id)

    # Set adapter unavailable
    local_adapter.set_available(False)

    resp = client.post(
        "/api/v1/blockchain/verify",
        headers={"Authorization": f"Bearer {token}"},
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


def test_verification_get_endpoint(client: TestClient):
    token, _ = _register_and_login(client, "get_ver_user")
    vault_id = _create_and_unlock_vault(client, token)
    doc_id = _upload_doc(client, token, vault_id)

    resp = client.get(
        f"/api/v1/blockchain/verify/{doc_id}?vault_id={vault_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert data["document_id"] == doc_id
    assert data["verified"] is True
    assert data["blockchain_match"] is True
