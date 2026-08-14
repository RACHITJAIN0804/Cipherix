"""
tests/test_auth.py
------------------
Test suite for JWT authentication and user management.

Coverage
--------
* Successful registration
* Duplicate registration (409)
* Successful login
* Incorrect password (401)
* Inactive user (403)
* Valid access token → /auth/me
* Expired access token (401)
* Invalid JWT signature (401)
* Malformed JWT (401)
* Missing Authorization header (401)
* Refresh token flow
* Refresh token used as access token (401)
* Access token used as refresh token (401)
* All sensitive data assertions (no password in response, no hash exposed)

All tests use an in-memory SQLite database and the FastAPI test client so
they run without touching the production database or filesystem.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

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


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def in_memory_engine():
    """
    Fresh in-memory SQLite engine per test — fully isolated.

    StaticPool is required so that all connections (create_all + session
    queries) share the same in-memory database.  Without it, SQLite creates
    a brand-new empty database for every new connection, causing
    "no such table" errors even after create_all has run.
    """
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
    """
    FastAPI TestClient that overrides get_db with the in-memory session.

    Dependency override replaces the real DB session so tests are fully
    isolated from production and test SQLite files.
    """
    app = create_app()

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REGISTER_URL = "/api/v1/auth/register"
_LOGIN_URL = "/api/v1/auth/login"
_ME_URL = "/api/v1/auth/me"
_REFRESH_URL = "/api/v1/auth/refresh"

_VALID_USERNAME = "testuser"
_VALID_PASSWORD = "securepass123"


def _register(client, username=_VALID_USERNAME, password=_VALID_PASSWORD):
    return client.post(
        _REGISTER_URL,
        json={"username": username, "password": password},
    )


def _login(client, username=_VALID_USERNAME, password=_VALID_PASSWORD):
    return client.post(
        _LOGIN_URL,
        json={"username": username, "password": password},
    )


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------


class TestRegister:
    def test_successful_registration(self, client):
        """POST /register → 201 with user data (no password hash)."""
        resp = _register(client)
        assert resp.status_code == status.HTTP_201_CREATED
        data = resp.json()
        assert data["username"] == _VALID_USERNAME
        assert data["is_active"] is True
        assert "id" in data
        assert "created_at" in data

    def test_password_hash_never_returned(self, client):
        """Registration response must never expose the password hash."""
        resp = _register(client)
        data = resp.json()
        assert "password" not in data
        assert "password_hash" not in data

    def test_duplicate_registration_returns_409(self, client):
        """Registering with an existing username → 409 Conflict."""
        _register(client)
        resp = _register(client)
        assert resp.status_code == status.HTTP_409_CONFLICT

    def test_short_username_fails_validation(self, client):
        """Username shorter than 3 chars → 422 Unprocessable Entity."""
        resp = _register(client, username="ab")
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_short_password_fails_validation(self, client):
        """Password shorter than 8 chars → 422 Unprocessable Entity."""
        resp = _register(client, password="short")
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_blank_username_fails_validation(self, client):
        """Whitespace-only username → 422 Unprocessable Entity."""
        resp = _register(client, username="   ")
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_username_is_stripped(self, client):
        """Leading/trailing whitespace is stripped from the username."""
        resp = client.post(
            _REGISTER_URL,
            json={"username": "  alice  ", "password": _VALID_PASSWORD},
        )
        assert resp.status_code == status.HTTP_201_CREATED
        assert resp.json()["username"] == "alice"


# ---------------------------------------------------------------------------
# Login tests
# ---------------------------------------------------------------------------


class TestLogin:
    def test_successful_login_returns_tokens(self, client):
        """POST /login → 200 with access_token and refresh_token."""
        _register(client)
        resp = _login(client)
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_incorrect_password_returns_401(self, client):
        """Wrong password → 401 Unauthorized."""
        _register(client)
        resp = _login(client, password="wrongpassword")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_nonexistent_user_returns_401(self, client):
        """Unknown username → 401 (same as wrong password — no enumeration)."""
        resp = _login(client, username="nobody")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_inactive_user_returns_403(self, client, db_session: Session):
        """Deactivated account → 403 Forbidden."""
        _register(client)
        # Deactivate the user directly in DB.
        user = db_session.query(User).filter(User.username == _VALID_USERNAME).first()
        user.is_active = False
        db_session.commit()

        resp = _login(client)
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    def test_password_not_returned_on_login(self, client):
        """Login response contains tokens, never the password."""
        _register(client)
        data = _login(client).json()
        assert "password" not in data
        assert "password_hash" not in data


# ---------------------------------------------------------------------------
# /auth/me tests
# ---------------------------------------------------------------------------


class TestMe:
    def test_me_with_valid_token(self, client):
        """GET /me with a valid access token → 200 with user profile."""
        _register(client)
        token = _login(client).json()["access_token"]
        resp = client.get(_ME_URL, headers=_auth_headers(token))
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["username"] == _VALID_USERNAME
        assert "password" not in data
        assert "password_hash" not in data

    def test_me_without_token_returns_401(self, client):
        """GET /me with no Authorization header → 401."""
        resp = client.get(_ME_URL)
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_me_with_malformed_token_returns_401(self, client):
        """GET /me with garbage token string → 401."""
        resp = client.get(_ME_URL, headers=_auth_headers("not.a.jwt"))
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_me_with_expired_token_returns_401(self, client):
        """GET /me with an expired access token → 401."""
        _register(client)
        # Create a token that expired in the past.
        now = datetime.now(UTC)
        expired_claims = {
            "sub": "any-id",
            "iat": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),
            "type": "access",
        }
        expired_token = jwt.encode(
            expired_claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
        )
        resp = client.get(_ME_URL, headers=_auth_headers(expired_token))
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_me_with_wrong_signature_returns_401(self, client):
        """GET /me with a token signed by a different secret → 401."""
        _register(client)
        now = datetime.now(UTC)
        claims = {
            "sub": "some-id",
            "iat": now,
            "exp": now + timedelta(hours=1),
            "type": "access",
        }
        forged_token = jwt.encode(claims, "wrong_secret", algorithm="HS256")
        resp = client.get(_ME_URL, headers=_auth_headers(forged_token))
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_me_with_refresh_token_returns_401(self, client):
        """GET /me with a refresh token (wrong type) → 401."""
        _register(client)
        refresh_token = _login(client).json()["refresh_token"]
        # Presenting a refresh token where an access token is required must fail.
        resp = client.get(_ME_URL, headers=_auth_headers(refresh_token))
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_me_inactive_user_returns_403(self, client, db_session: Session):
        """GET /me for a deactivated account → 403 Forbidden."""
        _register(client)
        token = _login(client).json()["access_token"]

        # Deactivate after login (token is still valid, but user is inactive).
        user = db_session.query(User).filter(User.username == _VALID_USERNAME).first()
        user.is_active = False
        db_session.commit()

        resp = client.get(_ME_URL, headers=_auth_headers(token))
        assert resp.status_code == status.HTTP_403_FORBIDDEN


# ---------------------------------------------------------------------------
# Refresh token tests
# ---------------------------------------------------------------------------


class TestRefresh:
    def test_refresh_returns_new_tokens(self, client):
        """POST /refresh with a valid refresh token → 200 with new token pair."""
        _register(client)
        refresh_token = _login(client).json()["refresh_token"]
        resp = client.post(_REFRESH_URL, json={"refresh_token": refresh_token})
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_refresh_with_access_token_fails(self, client):
        """POST /refresh with an access token (wrong type) → 401."""
        _register(client)
        access_token = _login(client).json()["access_token"]
        resp = client.post(_REFRESH_URL, json={"refresh_token": access_token})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_refresh_with_expired_token_fails(self, client):
        """POST /refresh with an expired refresh token → 401."""
        _register(client)
        now = datetime.now(UTC)
        expired_claims = {
            "sub": "some-id",
            "iat": now - timedelta(days=8),
            "exp": now - timedelta(days=1),
            "type": "refresh",
        }
        expired_token = jwt.encode(
            expired_claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
        )
        resp = client.post(_REFRESH_URL, json={"refresh_token": expired_token})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_refresh_with_malformed_token_fails(self, client):
        """POST /refresh with a garbage string → 401."""
        resp = client.post(_REFRESH_URL, json={"refresh_token": "garbage.token.here"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_new_access_token_works_for_me(self, client):
        """A new access token from /refresh must be accepted by /me."""
        _register(client)
        tokens = _login(client).json()
        new_tokens = client.post(
            _REFRESH_URL, json={"refresh_token": tokens["refresh_token"]}
        ).json()
        resp = client.get(_ME_URL, headers=_auth_headers(new_tokens["access_token"]))
        assert resp.status_code == status.HTTP_200_OK


# ---------------------------------------------------------------------------
# JWTManager unit tests
# ---------------------------------------------------------------------------


class TestJWTManager:
    """Direct unit tests for JWTManager — no HTTP layer."""

    def test_access_token_contains_expected_claims(self):
        from app.security.jwt_manager import JWTManager

        token = JWTManager.create_access_token("user-123")
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
        assert payload["sub"] == "user-123"
        assert payload["type"] == "access"
        assert "exp" in payload
        assert "iat" in payload

    def test_refresh_token_has_refresh_type(self):
        from app.security.jwt_manager import JWTManager

        token = JWTManager.create_refresh_token("user-456")
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
        assert payload["type"] == "refresh"

    def test_access_token_cannot_be_decoded_as_refresh(self):
        from app.core.exceptions import InvalidTokenError
        from app.security.jwt_manager import JWTManager

        token = JWTManager.create_access_token("user-789")
        with pytest.raises(InvalidTokenError):
            JWTManager.decode_refresh_token(token)

    def test_refresh_token_cannot_be_decoded_as_access(self):
        from app.core.exceptions import InvalidTokenError
        from app.security.jwt_manager import JWTManager

        token = JWTManager.create_refresh_token("user-789")
        with pytest.raises(InvalidTokenError):
            JWTManager.decode_access_token(token)

    def test_expired_token_raises_expired_error(self):
        from app.core.exceptions import ExpiredTokenError
        from app.security.jwt_manager import JWTManager

        now = datetime.now(UTC)
        claims = {
            "sub": "user-999",
            "iat": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),
            "type": "access",
        }
        token = jwt.encode(claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
        with pytest.raises(ExpiredTokenError):
            JWTManager.decode_access_token(token)

    def test_wrong_signature_raises_invalid_error(self):
        from app.core.exceptions import InvalidTokenError
        from app.security.jwt_manager import JWTManager

        now = datetime.now(UTC)
        claims = {
            "sub": "user-000",
            "iat": now,
            "exp": now + timedelta(hours=1),
            "type": "access",
        }
        token = jwt.encode(claims, "completely_wrong_secret", algorithm="HS256")
        with pytest.raises(InvalidTokenError):
            JWTManager.decode_access_token(token)

    def test_no_sensitive_data_in_token(self):
        """JWT claims must not contain passwords, keys, or seeds."""
        from app.security.jwt_manager import JWTManager

        token = JWTManager.create_access_token("user-sec")
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
        forbidden_keys = {
            "password", "password_hash", "master_key", "vault_key",
            "recovery_seed", "seed", "secret",
        }
        assert forbidden_keys.isdisjoint(payload.keys()), (
            f"Sensitive key found in JWT claims: {forbidden_keys & payload.keys()}"
        )


# ---------------------------------------------------------------------------
# User model security assertions
# ---------------------------------------------------------------------------


class TestUserModelSecurity:
    """Assert User ORM model does not have plaintext-sensitive columns."""

    def test_user_table_has_no_plaintext_password_column(self):
        cols = {c.name for c in User.__table__.columns}
        assert "password" not in cols
        # password_hash is OK; "password" alone is not.

    def test_user_table_has_no_token_column(self):
        cols = {c.name for c in User.__table__.columns}
        assert "token" not in cols
        assert "access_token" not in cols
        assert "refresh_token" not in cols

    def test_password_hash_is_stored_argon2id(self, db_session: Session):
        """Stored hash must be an Argon2id hash string (starts with $argon2id$)."""
        from app.services.auth_service import AuthService
        from app.schemas.auth import RegisterRequest

        svc = AuthService()
        svc.register(db_session, RegisterRequest(username="hashcheck", password="password123"))
        user = db_session.query(User).filter(User.username == "hashcheck").first()
        assert user.password_hash.startswith("$argon2id$")
        assert "password123" not in user.password_hash
