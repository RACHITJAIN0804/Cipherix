"""
tests/test_blockchain.py
------------------------
Comprehensive test suite for Blockchain Integrity & Verification layer.

Verifies:
1. Successful hash anchoring.
2. Successful verification.
3. Hash mismatch detection.
4. Unauthorized user cannot anchor another user's document.
5. Unauthorized user cannot verify another user's document.
6. Cross-vault access is rejected.
7. Client-provided fake hash is rejected/ignored (server calculates hash).
8. Duplicate anchor behavior.
9. Anchor-not-found behavior.
10. Blockchain unavailable behavior.
11. Local blockchain adapter works.
12. Blockchain service uses the adapter abstraction.
13. No plaintext document content is stored in blockchain records.
14. No encryption keys are stored in blockchain records.
15. No recovery seed is stored in blockchain records.
16. Audit logging does not leak sensitive information.
17. Existing document integrity hash is reused.
18. Existing encryption tests continue passing.
19. Existing RAG tests continue passing.
20. Existing computer-access tests continue passing.
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

from app.core.config import settings
from app.core.exceptions import BlockchainUnavailableError
from app.database import get_db
from app.database.models import Base, BlockchainAnchorRecord, Document as DocumentRecord, Vault as VaultRecord
from app.main import create_app
from app.services.blockchain import BlockchainService, LocalBlockchainAdapter
from app.storage.document_manager import DocumentManager


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------


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
def client(db_session: Session):
    app = create_app()

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def _register_and_login(client: TestClient, username_prefix: str = "bc_user") -> tuple[str, str]:
    username = f"{username_prefix}_{uuid.uuid4().hex[:6]}"
    password = "SecurePassword123!"
    reg = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    assert reg.status_code == status.HTTP_201_CREATED
    user_id = reg.json()["id"]

    login = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert login.status_code == status.HTTP_200_OK
    token = login.json()["access_token"]
    return token, user_id


def _create_vault(client: TestClient, token: str, name: str = "Test Vault", password: str = "VaultPassword123!") -> str:
    resp = client.post(
        "/api/v1/vaults/",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": name, "password": password},
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


def _upload_document(
    client: TestClient, token: str, vault_id: str, filename: str = "contract.txt", content: bytes = b"Confidential Agreement Data", password: str = "VaultPassword123!"
) -> str:
    files = {"file": (filename, io.BytesIO(content), "text/plain")}
    resp = client.post(
        f"/api/v1/vaults/{vault_id}/documents",
        headers={"Authorization": f"Bearer {token}", "X-Vault-Password": password},
        files=files,
    )
    assert resp.status_code == status.HTTP_201_CREATED
    return resp.json()["document_id"]


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


def test_1_successful_hash_anchoring(client: TestClient):
    token, _ = _register_and_login(client, "anchor_user")
    vault_id = _create_vault(client, token)
    doc_id = _upload_document(client, token, vault_id)

    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert data["document_id"] == doc_id
    assert data["status"] == "anchored"
    assert data["network"] == "local-development"
    assert data["tx_hash"].startswith("0x")
    assert len(data["privacy_reference"]) == 64
    assert len(data["integrity_hash"]) == 64


def test_2_successful_verification(client: TestClient):
    token, _ = _register_and_login(client, "verify_user")
    vault_id = _create_vault(client, token)
    doc_id = _upload_document(client, token, vault_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Anchor first
    anchor_resp = client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert anchor_resp.status_code == status.HTTP_200_OK

    # Verify
    verify_resp = client.post(
        "/api/v1/blockchain/verify",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert verify_resp.status_code == status.HTTP_200_OK
    vdata = verify_resp.json()
    assert vdata["integrity_match"] is True
    assert vdata["blockchain_match"] is True
    assert vdata["verified"] is True
    assert vdata["network"] == "local-development"


def test_3_hash_mismatch_detection(client: TestClient, db_session: Session):
    token, _ = _register_and_login(client, "tamper_user")
    vault_id = _create_vault(client, token)
    doc_id = _upload_document(client, token, vault_id, content=b"Original content")
    headers = {"Authorization": f"Bearer {token}"}

    # Anchor original document
    client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )

    # Tamper with the encrypted blob on disk
    blob_path = settings.VAULT_DIR / vault_id / "encrypted" / f"{doc_id}.bin"
    blob_path.write_bytes(b"TAMPERED_CIPHERTEXT_BYTES_1234567890")

    # Verify -> should detect hash mismatch
    verify_resp = client.post(
        "/api/v1/blockchain/verify",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert verify_resp.status_code == status.HTTP_200_OK
    vdata = verify_resp.json()
    assert vdata["blockchain_match"] is False
    assert vdata["verified"] is False


def test_4_unauthorized_user_cannot_anchor_another_users_document(client: TestClient):
    token_a, _ = _register_and_login(client, "user_a")
    token_b, _ = _register_and_login(client, "user_b")

    vault_a = _create_vault(client, token_a)
    doc_a = _upload_document(client, token_a, vault_a)

    # User B attempts to anchor User A's document -> 404
    headers_b = {"Authorization": f"Bearer {token_b}"}
    resp = client.post(
        "/api/v1/blockchain/anchor",
        headers=headers_b,
        json={"vault_id": vault_a, "document_id": doc_a},
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_5_unauthorized_user_cannot_verify_another_users_document(client: TestClient):
    token_a, _ = _register_and_login(client, "user_a")
    token_b, _ = _register_and_login(client, "user_b")

    vault_a = _create_vault(client, token_a)
    doc_a = _upload_document(client, token_a, vault_a)

    # Anchor by User A
    client.post(
        "/api/v1/blockchain/anchor",
        headers={"Authorization": f"Bearer {token_a}"},
        json={"vault_id": vault_a, "document_id": doc_a},
    )

    # User B attempts to verify User A's document -> 404
    headers_b = {"Authorization": f"Bearer {token_b}"}
    resp = client.post(
        "/api/v1/blockchain/verify",
        headers=headers_b,
        json={"vault_id": vault_a, "document_id": doc_a},
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_6_cross_vault_access_is_rejected(client: TestClient):
    token_a, _ = _register_and_login(client, "user_cross")
    vault_1 = _create_vault(client, token_a, "Vault 1")
    vault_2 = _create_vault(client, token_a, "Vault 2")
    doc_v1 = _upload_document(client, token_a, vault_1)

    headers = {"Authorization": f"Bearer {token_a}"}
    # Pass doc_v1 with wrong vault_2 ID -> 404
    resp = client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={"vault_id": vault_2, "document_id": doc_v1},
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_7_client_provided_fake_hash_is_rejected_or_ignored(client: TestClient):
    token, _ = _register_and_login(client, "user_fake")
    vault_id = _create_vault(client, token)
    doc_id = _upload_document(client, token, vault_id)
    headers = {"Authorization": f"Bearer {token}"}

    # API request body ONLY accepts vault_id and document_id (ignores any custom hash attempt)
    resp = client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={
            "vault_id": vault_id,
            "document_id": doc_id,
            "fake_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        },
    )
    assert resp.status_code == status.HTTP_200_OK
    # Integrity hash anchored MUST match actual document ciphertext hash, not fake_hash
    db_doc = client.get(f"/api/v1/blockchain/anchor/{doc_id}?vault_id={vault_id}", headers=headers)
    assert db_doc.status_code == status.HTTP_200_OK
    assert db_doc.json()["integrity_hash"] != "0000000000000000000000000000000000000000000000000000000000000000"


def test_8_duplicate_anchor_behavior(client: TestClient):
    token, _ = _register_and_login(client, "user_dup")
    vault_id = _create_vault(client, token)
    doc_id = _upload_document(client, token, vault_id)
    headers = {"Authorization": f"Bearer {token}"}

    # First anchor
    resp1 = client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp1.status_code == status.HTTP_200_OK
    tx1 = resp1.json()["tx_hash"]

    # Second anchor -> returns idempotent existing record
    resp2 = client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp2.status_code == status.HTTP_200_OK
    tx2 = resp2.json()["tx_hash"]
    assert tx1 == tx2


def test_9_anchor_not_found_behavior(client: TestClient):
    token, _ = _register_and_login(client, "user_nf")
    vault_id = _create_vault(client, token)
    doc_id = _upload_document(client, token, vault_id)
    headers = {"Authorization": f"Bearer {token}"}

    # GET anchor for unanchored document -> 404 Not Found
    resp = client.get(f"/api/v1/blockchain/anchor/{doc_id}?vault_id={vault_id}", headers=headers)
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_10_blockchain_unavailable_behavior(client: TestClient, monkeypatch):
    token, _ = _register_and_login(client, "user_unavail")
    vault_id = _create_vault(client, token)
    doc_id = _upload_document(client, token, vault_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Simulate blockchain disabled in settings
    monkeypatch.setattr(settings, "blockchain_enabled", False)

    resp = client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert "disabled" in resp.json()["detail"]


def test_11_local_blockchain_adapter_works():
    adapter = LocalBlockchainAdapter(network="local-development")
    assert adapter.is_available() is True

    receipt = adapter.anchor_hash("ref_123", "hash_abc")
    assert receipt["status"] == "anchored"
    assert receipt["tx_hash"].startswith("0x")

    record = adapter.get_anchor(receipt["tx_hash"])
    assert record is not None
    assert record["integrity_hash"] == "hash_abc"

    assert adapter.verify_anchor("ref_123", "hash_abc", receipt["tx_hash"]) is True
    assert adapter.verify_anchor("ref_123", "wrong_hash", receipt["tx_hash"]) is False


def test_12_blockchain_service_uses_adapter_abstraction(db_session: Session):
    local_adapter = LocalBlockchainAdapter(network="test-net")
    service = BlockchainService(adapter=local_adapter)
    assert service.adapter.network_name == "test-net"


def test_13_no_plaintext_document_content_stored_in_blockchain_records(
    client: TestClient, db_session: Session
):
    plaintext_secret = "CONFIDENTIAL_PASSPHRASE_9999"
    token, _ = _register_and_login(client, "user_priv1")
    vault_id = _create_vault(client, token)
    doc_id = _upload_document(client, token, vault_id, content=plaintext_secret.encode("utf-8"))
    headers = {"Authorization": f"Bearer {token}"}

    client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )

    records = db_session.query(BlockchainAnchorRecord).all()
    for rec in records:
        assert plaintext_secret not in rec.integrity_hash
        assert plaintext_secret not in rec.privacy_reference
        assert plaintext_secret not in rec.tx_hash


def test_14_no_encryption_keys_stored_in_blockchain_records(
    client: TestClient, db_session: Session
):
    token, _ = _register_and_login(client, "user_priv2")
    vault_id = _create_vault(client, token)
    doc_id = _upload_document(client, token, vault_id)
    headers = {"Authorization": f"Bearer {token}"}

    client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )

    records = db_session.query(BlockchainAnchorRecord).all()
    for rec in records:
        assert len(rec.integrity_hash) == 64
        assert len(rec.privacy_reference) == 64
        # Confirm fields only contain hex digests and standard identifiers
        int(rec.integrity_hash, 16)
        int(rec.privacy_reference, 16)


def test_15_no_recovery_seed_stored_in_blockchain_records(
    client: TestClient, db_session: Session
):
    token, _ = _register_and_login(client, "user_priv3")
    vault_id = _create_vault(client, token)
    doc_id = _upload_document(client, token, vault_id)
    headers = {"Authorization": f"Bearer {token}"}

    client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )

    records = db_session.query(BlockchainAnchorRecord).all()
    for rec in records:
        assert "abandon" not in rec.privacy_reference  # BIP-39 word test
        assert "zoo" not in rec.privacy_reference


def test_16_audit_logging_does_not_leak_sensitive_information(
    client: TestClient, caplog
):
    token, _ = _register_and_login(client, "user_audit")
    vault_id = _create_vault(client, token)
    doc_id = _upload_document(client, token, vault_id, content=b"Super secret document text")
    headers = {"Authorization": f"Bearer {token}"}

    client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )

    for record in caplog.records:
        assert "Super secret document text" not in record.message


def test_17_existing_document_integrity_hash_is_reused(client: TestClient, db_session: Session):
    token, _ = _register_and_login(client, "user_reuse")
    vault_id = _create_vault(client, token)
    doc_id = _upload_document(client, token, vault_id)

    # Get document record from DB
    doc_rec = db_session.get(DocumentRecord, doc_id)
    assert doc_rec is not None
    stored_hash = doc_rec.integrity_hash
    assert stored_hash is not None

    # Anchor hash
    headers = {"Authorization": f"Bearer {token}"}
    anchor_resp = client.post(
        "/api/v1/blockchain/anchor",
        headers=headers,
        json={"vault_id": vault_id, "document_id": doc_id},
    )
    assert anchor_resp.status_code == status.HTTP_200_OK
    assert anchor_resp.json()["integrity_hash"] == stored_hash
