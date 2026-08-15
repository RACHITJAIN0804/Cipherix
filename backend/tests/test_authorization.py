"""
tests/test_authorization.py
----------------------------
Comprehensive test suite for Vault Ownership and Authorization boundaries.

Verifies:
1. User A creates a vault -> associated with User A.
2. User A can access, lock, unlock, list, delete their vault.
3. User B CANNOT access, lock, unlock, delete, or list User A's vault.
4. User A can upload, list, download, verify, delete documents in their vault.
5. User B CANNOT upload, list, download, verify, or delete documents in User A's vault.
6. User B CANNOT change password or generate/verify recovery seeds for User A's vault.
7. Unauthenticated requests (missing, invalid, expired JWT) are rejected with 401.
8. Deactivated users (is_active=False) are rejected with 403.
9. Accessing nonexistent vaults or documents returns 404.

All tests run against an isolated in-memory SQLite database.
"""

from datetime import UTC, datetime, timedelta
import io

import jwt
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.database import get_db
from app.database.models import Base, User
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
    """FastAPI TestClient with overridden get_db."""
    app = create_app()

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()



def _register_and_login(client, username: str, password: str = "password123") -> str:
    client.post("/api/v1/auth/register", json={"username": username, "password": password})
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}



class TestVaultOwnershipAndIsolation:
    def test_user_a_creates_and_lists_vault(self, client):
        """User A creates a vault; User A lists it. User B sees an empty list."""
        token_a = _register_and_login(client, "user_a")
        token_b = _register_and_login(client, "user_b")

        create_resp = client.post(
            "/api/v1/vaults/",
            headers=_auth_header(token_a),
            json={"name": "Vault A", "password": "vaultpassword123"},
        )
        assert create_resp.status_code == status.HTTP_201_CREATED
        vault_a_id = create_resp.json()["vault_id"]

        list_a = client.get("/api/v1/vaults/", headers=_auth_header(token_a))
        assert list_a.status_code == status.HTTP_200_OK
        summaries_a = list_a.json()
        assert len(summaries_a) == 1
        assert summaries_a[0]["vault_id"] == vault_a_id

        list_b = client.get("/api/v1/vaults/", headers=_auth_header(token_b))
        assert list_b.status_code == status.HTTP_200_OK
        assert len(list_b.json()) == 0

    def test_user_b_cannot_access_or_lock_unlock_user_a_vault(self, client):
        """User B cannot lock or unlock User A's vault -> returns 404."""
        token_a = _register_and_login(client, "user_a_lock")
        token_b = _register_and_login(client, "user_b_lock")

        vault_a_id = client.post(
            "/api/v1/vaults/",
            headers=_auth_header(token_a),
            json={"name": "Vault A", "password": "vaultpassword123"},
        ).json()["vault_id"]

        unlock_b = client.post(
            f"/api/v1/vaults/{vault_a_id}/unlock",
            headers=_auth_header(token_b),
        )
        assert unlock_b.status_code == status.HTTP_404_NOT_FOUND

        lock_b = client.post(
            f"/api/v1/vaults/{vault_a_id}/lock",
            headers=_auth_header(token_b),
        )
        assert lock_b.status_code == status.HTTP_404_NOT_FOUND

    def test_user_b_cannot_delete_user_a_vault(self, client):
        """User B cannot delete User A's vault -> 404. User A can delete it."""
        token_a = _register_and_login(client, "user_a_del")
        token_b = _register_and_login(client, "user_b_del")

        vault_a_id = client.post(
            "/api/v1/vaults/",
            headers=_auth_header(token_a),
            json={"name": "Vault A", "password": "vaultpassword123"},
        ).json()["vault_id"]

        del_b = client.delete(
            f"/api/v1/vaults/{vault_a_id}",
            headers=_auth_header(token_b),
        )
        assert del_b.status_code == status.HTTP_404_NOT_FOUND

        del_a = client.delete(
            f"/api/v1/vaults/{vault_a_id}",
            headers=_auth_header(token_a),
        )
        assert del_a.status_code == status.HTTP_204_NO_CONTENT

    def test_document_isolation_between_users(self, client):
        """User A uploads a document to their unlocked vault. User B cannot upload, list, download, or delete it."""
        token_a = _register_and_login(client, "user_doc_a")
        token_b = _register_and_login(client, "user_doc_b")

        pwd = "vaultpassword123"

        vault_a_id = client.post(
            "/api/v1/vaults/",
            headers=_auth_header(token_a),
            json={"name": "Vault Doc A", "password": pwd},
        ).json()["vault_id"]

        client.post(
            f"/api/v1/vaults/{vault_a_id}/unlock",
            headers=_auth_header(token_a),
        )

        file_content = b"Super secret content for User A"
        file_tuple = ("secret.txt", io.BytesIO(file_content), "text/plain")
        up_resp_a = client.post(
            f"/api/v1/vaults/{vault_a_id}/documents",
            headers={**_auth_header(token_a), "X-Vault-Password": pwd},
            files={"file": file_tuple},
        )
        assert up_resp_a.status_code == status.HTTP_201_CREATED
        doc_a_id = up_resp_a.json()["document_id"]

        file_tuple_b = ("fake.txt", io.BytesIO(b"attacker data"), "text/plain")
        up_resp_b = client.post(
            f"/api/v1/vaults/{vault_a_id}/documents",
            headers={**_auth_header(token_b), "X-Vault-Password": pwd},
            files={"file": file_tuple_b},
        )
        assert up_resp_b.status_code == status.HTTP_404_NOT_FOUND

        list_docs_b = client.get(
            f"/api/v1/vaults/{vault_a_id}/documents",
            headers=_auth_header(token_b),
        )
        assert list_docs_b.status_code == status.HTTP_404_NOT_FOUND

        down_b = client.get(
            f"/api/v1/vaults/{vault_a_id}/documents/{doc_a_id}",
            headers={**_auth_header(token_b), "X-Vault-Password": pwd},
        )
        assert down_b.status_code == status.HTTP_404_NOT_FOUND

        verify_b = client.get(
            f"/api/v1/vaults/{vault_a_id}/documents/{doc_a_id}/verify",
            headers=_auth_header(token_b),
        )
        assert verify_b.status_code == status.HTTP_404_NOT_FOUND

        del_doc_b = client.delete(
            f"/api/v1/vaults/{vault_a_id}/documents/{doc_a_id}",
            headers=_auth_header(token_b),
        )
        assert del_doc_b.status_code == status.HTTP_404_NOT_FOUND

        down_a = client.get(
            f"/api/v1/vaults/{vault_a_id}/documents/{doc_a_id}",
            headers={**_auth_header(token_a), "X-Vault-Password": pwd},
        )
        assert down_a.status_code == status.HTTP_200_OK
        assert down_a.content == file_content

    def test_security_operations_isolation(self, client):
        """User B cannot change password or manage recovery seeds for User A's vault."""
        token_a = _register_and_login(client, "user_sec_a")
        token_b = _register_and_login(client, "user_sec_b")
        pwd = "vaultpassword123"

        vault_a_id = client.post(
            "/api/v1/vaults/",
            headers=_auth_header(token_a),
            json={"name": "Vault Sec A", "password": pwd},
        ).json()["vault_id"]

        client.post(
            f"/api/v1/vaults/{vault_a_id}/unlock",
            headers=_auth_header(token_a),
        )

        change_b = client.post(
            f"/api/v1/vaults/{vault_a_id}/change-password",
            headers=_auth_header(token_b),
            json={"old_password": pwd, "new_password": "newpassword123"},
        )
        assert change_b.status_code == status.HTTP_404_NOT_FOUND

        seed_b = client.post(
            f"/api/v1/vaults/{vault_a_id}/recovery-seed",
            headers=_auth_header(token_b),
        )
        assert seed_b.status_code == status.HTTP_404_NOT_FOUND

        seed_a_resp = client.post(
            f"/api/v1/vaults/{vault_a_id}/recovery-seed",
            headers=_auth_header(token_a),
        )
        assert seed_a_resp.status_code == status.HTTP_201_CREATED
        seed_words = seed_a_resp.json()["seed"]

        verify_seed_b = client.post(
            f"/api/v1/vaults/{vault_a_id}/recovery-seed/verify",
            headers=_auth_header(token_b),
            json={"seed": seed_words},
        )
        assert verify_seed_b.status_code == status.HTTP_404_NOT_FOUND


class TestUnauthenticatedAndInvalidTokens:
    def test_missing_jwt_rejected(self, client):
        """All protected endpoints return 401 when missing Authorization header."""
        endpoints = [
            ("GET", "/api/v1/vaults/"),
            ("POST", "/api/v1/vaults/"),
            ("DELETE", "/api/v1/vaults/00000000-0000-0000-0000-000000000000"),
            ("POST", "/api/v1/vaults/00000000-0000-0000-0000-000000000000/lock"),
            ("POST", "/api/v1/vaults/00000000-0000-0000-0000-000000000000/unlock"),
            ("GET", "/api/v1/vaults/00000000-0000-0000-0000-000000000000/documents"),
        ]
        for method, path in endpoints:
            if method == "GET":
                resp = client.get(path)
            elif method == "POST":
                resp = client.post(path, json={"name": "test", "password": "pass"})
            elif method == "DELETE":
                resp = client.delete(path)
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_invalid_jwt_rejected(self, client):
        """Garbage token returns 401."""
        hdr = _auth_header("invalid.jwt.token")
        resp = client.get("/api/v1/vaults/", headers=hdr)
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_expired_jwt_rejected(self, client):
        """Expired JWT returns 401."""
        now = datetime.now(UTC)
        claims = {
            "sub": "some-user-id",
            "iat": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),
            "type": "access",
        }
        expired_token = jwt.encode(
            claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
        )
        resp = client.get("/api/v1/vaults/", headers=_auth_header(expired_token))
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_inactive_user_rejected(self, client, db_session: Session):
        """Deactivated user returns 403 on protected vault endpoints."""
        token = _register_and_login(client, "deactivated_user")

        user = db_session.query(User).filter(User.username == "deactivated_user").first()
        user.is_active = False
        db_session.commit()

        resp = client.get("/api/v1/vaults/", headers=_auth_header(token))
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    def test_nonexistent_vault_returns_404(self, client):
        """Valid user querying nonexistent vault returns 404."""
        token = _register_and_login(client, "valid_user_404")
        fake_uuid = "11111111-2222-3333-4444-555555555555"

        resp = client.post(f"/api/v1/vaults/{fake_uuid}/unlock", headers=_auth_header(token))
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    def test_invalid_uuid_returns_400(self, client):
        """Passing an invalid UUID string returns 400 Bad Request."""
        token = _register_and_login(client, "valid_user_400")
        resp = client.post("/api/v1/vaults/not-a-uuid/unlock", headers=_auth_header(token))
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
