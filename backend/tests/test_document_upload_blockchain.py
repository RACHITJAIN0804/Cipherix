"""
tests/test_document_upload_blockchain.py
-----------------------------------------
Focused test suite for Step 6: Integrating Blockchain Hash Recording with Document Upload.

Verifies:
1. Document upload automatically records SHA-256 hash of encrypted document on blockchain.
2. Stored blockchain hash exactly matches the SHA-256 hash of the encrypted document.
3. Blockchain record is associated with document_id, vault_id, encrypted document hash, timestamp, tx_hash, network.
4. No plaintext document data, encryption keys, or recovery seed phrases are stored on-chain.
5. Blockchain failure prevents document creation (no orphan DB records, no orphan files on disk).
6. Upload succeeds when blockchain is disabled in settings (backward compatibility).
"""

import hashlib
import io
import uuid
from pathlib import Path

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.exceptions import BlockchainUnavailableError
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


def _register_and_login(client: TestClient, username_prefix: str = "upload_bc_user") -> tuple[str, str]:
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
        json={"name": "Upload Vault", "password": password},
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


def test_upload_records_blockchain_hash(client: TestClient, db_session: Session):
    token, user_id = _register_and_login(client, "upload_success")
    vault_id = _create_and_unlock_vault(client, token)

    file_content = b"Top secret classified data for step 6 test."
    files = {"file": ("classified.txt", io.BytesIO(file_content), "text/plain")}

    resp = client.post(
        f"/api/v1/vaults/{vault_id}/documents",
        headers={"Authorization": f"Bearer {token}", "X-Vault-Password": "VaultPassword123!"},
        files=files,
    )
    assert resp.status_code == status.HTTP_201_CREATED
    doc_id = resp.json()["document_id"]

    # Verify Document record in DB
    doc_rec = db_session.get(DocumentRecord, doc_id)
    assert doc_rec is not None
    assert doc_rec.vault_id == vault_id

    # Verify BlockchainAnchorRecord in DB
    anchor_rec = (
        db_session.query(BlockchainAnchorRecord)
        .filter(BlockchainAnchorRecord.document_id == doc_id)
        .first()
    )
    assert anchor_rec is not None
    assert anchor_rec.document_id == doc_id
    assert anchor_rec.vault_id == vault_id
    assert anchor_rec.status == "anchored"
    assert anchor_rec.network == "local-development"
    assert anchor_rec.tx_hash.startswith("0x")
    assert anchor_rec.created_at is not None

    # Read encrypted blob from disk and verify exact SHA-256 match
    blob_path = settings.VAULT_DIR / vault_id / "encrypted" / f"{doc_id}.bin"
    assert blob_path.is_file()
    ciphertext = blob_path.read_bytes()
    expected_sha256 = hashlib.sha256(ciphertext).hexdigest()

    assert anchor_rec.integrity_hash == expected_sha256
    assert doc_rec.integrity_hash == expected_sha256

    # Verify privacy principles
    assert file_content.decode("utf-8") not in anchor_rec.integrity_hash
    assert file_content.decode("utf-8") not in anchor_rec.privacy_reference


def test_upload_rollback_on_blockchain_failure(client: TestClient, db_session: Session, local_adapter: LocalBlockchainAdapter):
    token, user_id = _register_and_login(client, "upload_fail")
    vault_id = _create_and_unlock_vault(client, token)

    # Disable local blockchain adapter to simulate RPC network failure
    local_adapter.set_available(False)

    file_content = b"This upload should fail cleanly without corrupting state."
    files = {"file": ("fail_doc.txt", io.BytesIO(file_content), "text/plain")}

    resp = client.post(
        f"/api/v1/vaults/{vault_id}/documents",
        headers={"Authorization": f"Bearer {token}", "X-Vault-Password": "VaultPassword123!"},
        files=files,
    )
    assert resp.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    # Verify NO DocumentRecord exists in DB
    doc_recs = db_session.query(DocumentRecord).filter(DocumentRecord.vault_id == vault_id).all()
    assert len(doc_recs) == 0

    # Verify NO BlockchainAnchorRecord exists in DB
    anchor_recs = db_session.query(BlockchainAnchorRecord).filter(BlockchainAnchorRecord.vault_id == vault_id).all()
    assert len(anchor_recs) == 0

    # Verify NO leftover blob or metadata files on disk
    vault_encrypted_dir = settings.VAULT_DIR / vault_id / "encrypted"
    if vault_encrypted_dir.is_dir():
        files_on_disk = list(vault_encrypted_dir.glob("*.bin"))
        assert len(files_on_disk) == 0

    vault_meta_dir = settings.VAULT_DIR / vault_id / "metadata"
    if vault_meta_dir.is_dir():
        meta_on_disk = list(vault_meta_dir.glob("*.json"))
        assert len(meta_on_disk) == 0


def test_upload_when_blockchain_disabled(client: TestClient, db_session: Session, monkeypatch):
    token, user_id = _register_and_login(client, "upload_disabled_bc")
    vault_id = _create_and_unlock_vault(client, token)

    # Disable blockchain in settings
    monkeypatch.setattr(settings, "blockchain_enabled", False)

    file_content = b"Document uploaded when blockchain is disabled in config."
    files = {"file": ("noblockchain.txt", io.BytesIO(file_content), "text/plain")}

    resp = client.post(
        f"/api/v1/vaults/{vault_id}/documents",
        headers={"Authorization": f"Bearer {token}", "X-Vault-Password": "VaultPassword123!"},
        files=files,
    )
    assert resp.status_code == status.HTTP_201_CREATED
    doc_id = resp.json()["document_id"]

    # Document should exist in DB and filesystem
    doc_rec = db_session.get(DocumentRecord, doc_id)
    assert doc_rec is not None

    # No blockchain anchor record created
    anchor_rec = (
        db_session.query(BlockchainAnchorRecord)
        .filter(BlockchainAnchorRecord.document_id == doc_id)
        .first()
    )
    assert anchor_rec is None
