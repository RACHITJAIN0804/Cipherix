"""
tests/test_dashboard_document_count.py
---------------------------------------
Regression test suite for Dashboard Document Count Bug.

Verifies:
1. A newly registered user with their initial vault has 0 documents (never hardcoded 5).
2. A user with one document sees exactly 1.
3. A user with multiple documents across multiple vaults sees the exact count.
4. Uploading a document increments the document count in real-time.
5. Deleting a document decrements the document count in real-time.
6. Strict user and vault isolation: User A's documents do not increment User B's document count.
7. An empty vault reports 0 documents.
8. If a user deletes all vaults, /vaults/ returns [] and document count is 0.
9. VaultSummary schema contains document_count accurately populated from database.
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
from app.core.rate_limiter import _limiter
from app.database import get_db
from app.database.models import Base
from app.main import create_app


@pytest.fixture(scope="function")
def in_memory_engine(tmp_path, monkeypatch):
    """Isolated in-memory SQLite engine with StaticPool + temp vault directory."""
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
    """Yield a session and roll back after each test."""
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
    """FastAPI TestClient with overridden get_db and cleared rate limiter."""
    _limiter.clear()
    app = create_app()

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


def _register_and_login(client: TestClient, username: str, password: str = "Password123!") -> tuple[str, str]:
    """Register a new user (which auto-provisions their initial vault) and log in."""
    r = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    assert r.status_code == status.HTTP_201_CREATED
    data = r.json()
    default_vault_id = data.get("vault_id")

    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert resp.status_code == status.HTTP_200_OK
    token = resp.json()["access_token"]
    return token, default_vault_id


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _unlock_vault(client: TestClient, token: str, vault_id: str) -> None:
    unlock_resp = client.post(
        f"/api/v1/vaults/{vault_id}/unlock",
        headers=_auth_header(token),
    )
    assert unlock_resp.status_code == status.HTTP_200_OK


def _create_and_unlock_vault(client: TestClient, token: str, vault_name: str = "Test Vault", password: str = "VaultPass123!") -> str:
    create_resp = client.post(
        "/api/v1/vaults/",
        headers=_auth_header(token),
        json={"name": vault_name, "password": password},
    )
    assert create_resp.status_code == status.HTTP_201_CREATED
    vault_id = create_resp.json()["vault_id"]
    _unlock_vault(client, token, vault_id)
    return vault_id


def _upload_document(client: TestClient, token: str, vault_id: str, filename: str, content: bytes, password: str = "Password123!") -> str:
    file_tuple = (filename, io.BytesIO(content), "text/plain")
    upload_resp = client.post(
        f"/api/v1/vaults/{vault_id}/documents",
        headers={**_auth_header(token), "X-Vault-Password": password},
        files={"file": file_tuple},
    )
    assert upload_resp.status_code == status.HTTP_201_CREATED
    return upload_resp.json()["document_id"]


class TestDashboardDocumentCountRegression:
    def test_user_with_zero_documents_sees_zero(self, client: TestClient):
        """A user with an empty vault must see 0 documents, never the hardcoded fallback 5."""
        token, vault_id = _register_and_login(client, "user_zero_docs")
        _unlock_vault(client, token, vault_id)

        resp = client.get("/api/v1/vaults/", headers=_auth_header(token))
        assert resp.status_code == status.HTTP_200_OK
        vaults = resp.json()
        assert len(vaults) == 1
        assert vaults[0]["document_count"] == 0
        assert vaults[0]["document_count"] != 5

        doc_resp = client.get(f"/api/v1/vaults/{vault_id}/documents", headers=_auth_header(token))
        assert doc_resp.status_code == status.HTTP_200_OK
        data = doc_resp.json()
        assert data["count"] == 0
        assert len(data["documents"]) == 0

    def test_user_with_one_document_sees_one(self, client: TestClient):
        """User with 1 document uploaded sees exactly 1."""
        token, vault_id = _register_and_login(client, "user_one_doc")
        _unlock_vault(client, token, vault_id)

        _upload_document(client, token, vault_id, "doc1.txt", b"Hello world 1")

        resp = client.get("/api/v1/vaults/", headers=_auth_header(token))
        assert resp.status_code == status.HTTP_200_OK
        vaults = resp.json()
        assert len(vaults) == 1
        assert vaults[0]["document_count"] == 1

        doc_resp = client.get(f"/api/v1/vaults/{vault_id}/documents", headers=_auth_header(token))
        assert doc_resp.status_code == status.HTTP_200_OK
        assert doc_resp.json()["count"] == 1

    def test_user_with_multiple_documents_sees_correct_count(self, client: TestClient):
        """User with multiple documents across multiple vaults sees exact aggregate counts."""
        token, vault_a = _register_and_login(client, "user_multi_docs")
        _unlock_vault(client, token, vault_a)
        vault_b = _create_and_unlock_vault(client, token, "Vault B", password="Password123!")

        _upload_document(client, token, vault_a, "a1.txt", b"File A1")
        _upload_document(client, token, vault_a, "a2.txt", b"File A2")
        _upload_document(client, token, vault_a, "a3.txt", b"File A3")

        _upload_document(client, token, vault_b, "b1.txt", b"File B1")
        _upload_document(client, token, vault_b, "b2.txt", b"File B2")

        resp = client.get("/api/v1/vaults/", headers=_auth_header(token))
        assert resp.status_code == status.HTTP_200_OK
        vaults = {v["vault_id"]: v["document_count"] for v in resp.json()}

        assert vaults[vault_a] == 3
        assert vaults[vault_b] == 2
        total_docs = sum(vaults.values())
        assert total_docs == 5

    def test_upload_and_delete_lifecycle_updates_count(self, client: TestClient):
        """Uploading increments count, deleting decrements count dynamically."""
        token, vault_id = _register_and_login(client, "user_lifecycle_docs")
        _unlock_vault(client, token, vault_id)

        r0 = client.get("/api/v1/vaults/", headers=_auth_header(token))
        assert r0.json()[0]["document_count"] == 0

        d1 = _upload_document(client, token, vault_id, "file1.txt", b"Content 1")
        r1 = client.get("/api/v1/vaults/", headers=_auth_header(token))
        assert r1.json()[0]["document_count"] == 1

        d2 = _upload_document(client, token, vault_id, "file2.txt", b"Content 2")
        r2 = client.get("/api/v1/vaults/", headers=_auth_header(token))
        assert r2.json()[0]["document_count"] == 2

        del_resp = client.delete(
            f"/api/v1/vaults/{vault_id}/documents/{d1}",
            headers=_auth_header(token),
        )
        assert del_resp.status_code == status.HTTP_204_NO_CONTENT

        r3 = client.get("/api/v1/vaults/", headers=_auth_header(token))
        assert r3.json()[0]["document_count"] == 1

        del_resp2 = client.delete(
            f"/api/v1/vaults/{vault_id}/documents/{d2}",
            headers=_auth_header(token),
        )
        assert del_resp2.status_code == status.HTTP_204_NO_CONTENT

        r4 = client.get("/api/v1/vaults/", headers=_auth_header(token))
        assert r4.json()[0]["document_count"] == 0

    def test_user_isolation_document_count(self, client: TestClient):
        """User A's documents must never be counted for User B."""
        token_a, vault_a = _register_and_login(client, "user_iso_a")
        token_b, vault_b = _register_and_login(client, "user_iso_b")

        _unlock_vault(client, token_a, vault_a)
        _unlock_vault(client, token_b, vault_b)

        for i in range(3):
            _upload_document(client, token_a, vault_a, f"user_a_{i}.txt", f"data {i}".encode())

        res_a = client.get("/api/v1/vaults/", headers=_auth_header(token_a))
        assert res_a.json()[0]["document_count"] == 3

        res_b = client.get("/api/v1/vaults/", headers=_auth_header(token_b))
        assert res_b.json()[0]["document_count"] == 0

        res_cross = client.get(f"/api/v1/vaults/{vault_a}/documents", headers=_auth_header(token_b))
        assert res_cross.status_code == status.HTTP_404_NOT_FOUND

    def test_user_deletes_all_vaults_sees_empty_list(self, client: TestClient):
        """When a user deletes their vault, /vaults/ returns [] and has 0 documents."""
        token, vault_id = _register_and_login(client, "user_del_all_vaults")
        del_resp = client.delete(f"/api/v1/vaults/{vault_id}", headers=_auth_header(token))
        assert del_resp.status_code == status.HTTP_204_NO_CONTENT

        resp = client.get("/api/v1/vaults/", headers=_auth_header(token))
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json() == []
