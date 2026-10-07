"""
tests/test_recovery.py
---------------------
Test suite for vault recovery using BIP-39 recovery seed.
"""

import io
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.models import User, Vault as VaultRecord
from app.main import create_app
from app.database import get_db


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
    from app.core.rate_limiter import _limiter
    _limiter.clear()
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


def _register_and_login(client, username: str = "recoveryuser", password: str = "OldPassword123!") -> dict:
    reg_resp = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    # New register endpoint returns access_token directly; fall back to login if needed.
    if reg_resp.status_code == 201 and "access_token" in reg_resp.json():
        token = reg_resp.json()["access_token"]
    else:
        resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
        token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestVaultRecovery:
    def test_full_recovery_flow_and_document_integrity(self, client, tmp_path):
        username = "rec_user_1"
        old_pass = "OldPassword123!"
        new_pass = "NewPassword123!"

        # Registration now creates user + vault + recovery seed atomically.
        # Capture the vault_id from the registration response.
        reg_resp = client.post(
            "/api/v1/auth/register",
            json={"username": username, "password": old_pass},
        )
        assert reg_resp.status_code == status.HTTP_201_CREATED
        reg_data = reg_resp.json()
        token = reg_data["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        v_id = reg_data["vault_id"]

        # Unlock the vault (it was locked after recovery seed setup)
        un_res = client.post(f"/api/v1/vaults/{v_id}/unlock", headers=headers)
        assert un_res.status_code == status.HTTP_200_OK

        # Upload document
        doc_content = b"Top secret file content before password loss"
        doc_res = client.post(
            f"/api/v1/vaults/{v_id}/documents",
            headers={**headers, "X-Vault-Password": old_pass},
            files={"file": ("secret.txt", io.BytesIO(doc_content), "text/plain")},
        )
        assert doc_res.status_code == status.HTTP_201_CREATED
        doc_id = doc_res.json()["document_id"]

        # Save pre-recovery ciphertext bytes from disk
        blob_path = settings.VAULT_DIR / v_id / "encrypted" / f"{doc_id}.bin"
        assert blob_path.is_file()
        pre_recovery_ciphertext = blob_path.read_bytes()

        # Lock vault (simulate forgotten password)
        client.post(f"/api/v1/vaults/{v_id}/lock", headers=headers)

        # Recover vault via POST /api/v1/auth/recover
        rec_res = client.post(
            "/api/v1/auth/recover",
            json={
                "username": username,
                "seed": reg_data["seed"],
                "new_password": new_pass,
            },
        )
        assert rec_res.status_code == status.HTTP_200_OK
        rec_tokens = rec_res.json()
        assert "access_token" in rec_tokens
        assert "refresh_token" in rec_tokens

        new_headers = {"Authorization": f"Bearer {rec_tokens['access_token']}"}

        # Unlock vault with new_password
        un_new = client.post(f"/api/v1/vaults/{v_id}/unlock", headers=new_headers)
        assert un_new.status_code == status.HTTP_200_OK

        # Post-recovery ciphertext on disk must be EXACTLY identical to pre-recovery ciphertext
        post_recovery_ciphertext = blob_path.read_bytes()
        assert post_recovery_ciphertext == pre_recovery_ciphertext

        # Download document using new_password -> content must match original!
        dl_res = client.get(
            f"/api/v1/vaults/{v_id}/documents/{doc_id}",
            headers={**new_headers, "X-Vault-Password": new_pass},
        )
        assert dl_res.status_code == status.HTTP_200_OK
        assert dl_res.content == doc_content

    def test_invalid_seed_format_returns_422(self, client):
        username = "fmt_user"
        old_pass = "OldPassword123!"
        headers = _register_and_login(client, username=username, password=old_pass)
        client.post("/api/v1/vaults/", headers=headers, json={"name": "Vault Fmt", "password": old_pass})

        rec_res = client.post(
            "/api/v1/auth/recover",
            json={
                "username": username,
                "seed": "invalid seed word count",
                "new_password": "NewPassword123!",
            },
        )
        assert rec_res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


    def test_wrong_seed_fingerprint_mismatch_returns_422(self, client):
        username = "rec_user_2"
        old_pass = "OldPassword123!"
        headers = _register_and_login(client, username=username, password=old_pass)

        v_res = client.post("/api/v1/vaults/", headers=headers, json={"name": "Vault 2", "password": old_pass})
        v_id = v_res.json()["vault_id"]
        client.post(f"/api/v1/vaults/{v_id}/unlock", headers=headers)

        from app.services.security_service import SecurityService
        sec_svc = SecurityService(vault_base_dir=settings.VAULT_DIR)
        sec_svc.generate_recovery_seed(v_id, password=old_pass)

        # Candidate seed for another vault (valid 16-word BIP-39 seed)
        from app.security.recovery import RecoveryManager
        wrong_seed = RecoveryManager(settings.VAULT_DIR).generate_seed("other-vault")

        rec_res = client.post(
            "/api/v1/auth/recover",
            json={
                "username": username,
                "seed": wrong_seed,
                "new_password": "NewPassword123!",
            },
        )
        assert rec_res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_nonexistent_user_returns_404(self, client):
        from app.security.recovery import RecoveryManager
        seed = RecoveryManager(settings.VAULT_DIR).generate_seed("dummy-vault")
        rec_res = client.post(
            "/api/v1/auth/recover",
            json={
                "username": "nobody_user",
                "seed": seed,
                "new_password": "NewPassword123!",
            },
        )
        assert rec_res.status_code == status.HTTP_404_NOT_FOUND

    def test_deactivated_user_cannot_recover(self, client, db_session: Session):
        username = "deact_user"
        headers = _register_and_login(client, username=username)

        v_res = client.post("/api/v1/vaults/", headers=headers, json={"name": "Vault 3", "password": "OldPassword123!"})
        v_id = v_res.json()["vault_id"]
        client.post(f"/api/v1/vaults/{v_id}/unlock", headers=headers)

        from app.services.security_service import SecurityService
        sec_svc = SecurityService(vault_base_dir=settings.VAULT_DIR)
        gen = sec_svc.generate_recovery_seed(v_id, password="OldPassword123!")

        # Deactivate user
        u = db_session.query(User).filter(User.username == username).first()
        u.is_active = False
        db_session.commit()

        rec_res = client.post(
            "/api/v1/auth/recover",
            json={
                "username": username,
                "seed": gen.seed,
                "new_password": "NewPassword123!",
            },
        )
        assert rec_res.status_code == status.HTTP_403_FORBIDDEN

    def test_recovery_seed_never_persisted(self, client):
        username = "rec_user_nopub"
        headers = _register_and_login(client, username=username)

        v_res = client.post("/api/v1/vaults/", headers=headers, json={"name": "Vault 4", "password": "OldPassword123!"})
        v_id = v_res.json()["vault_id"]
        client.post(f"/api/v1/vaults/{v_id}/unlock", headers=headers)

        from app.services.security_service import SecurityService
        sec_svc = SecurityService(vault_base_dir=settings.VAULT_DIR)
        gen = sec_svc.generate_recovery_seed(v_id, password="OldPassword123!")

        vault_dir = settings.VAULT_DIR / v_id
        for json_file in vault_dir.glob("*.json"):
            content = json_file.read_text(encoding="utf-8")
            assert gen.seed not in content

    def test_twelve_word_seed_fails_for_sixteen_word_flow(self, client):
        """Standard 12-word mnemonic must fail since Cipherix requires exactly 16 words."""
        username = "twelve_user"
        old_pass = "OldPassword123!"
        _register_and_login(client, username=username, password=old_pass)

        twelve_word_seed = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        assert len(twelve_word_seed.split()) == 12

        rec_res = client.post(
            "/api/v1/auth/recover",
            json={
                "username": username,
                "seed": twelve_word_seed,
                "new_password": "NewPassword123!",
            },
        )
        assert rec_res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_login_with_new_password_after_recovery_and_old_password_fails(self, client):
        """After recovery, normal login with new password succeeds and old password fails."""
        username = "rec_login_user"
        old_pass = "OldPassword123!"
        new_pass = "BrandNewPassword123!"

        reg_res = client.post(
            "/api/v1/auth/register",
            json={"username": username, "password": old_pass},
        )
        assert reg_res.status_code == status.HTTP_201_CREATED
        seed = reg_res.json()["seed"]

        # Recover account
        rec_res = client.post(
            "/api/v1/auth/recover",
            json={
                "username": username,
                "seed": seed,
                "new_password": new_pass,
            },
        )
        assert rec_res.status_code == status.HTTP_200_OK

        # Login with old password must fail
        old_login = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": old_pass},
        )
        assert old_login.status_code == status.HTTP_401_UNAUTHORIZED

        # Login with new password must succeed WITHOUT seed
        new_login = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": new_pass},
        )
        assert new_login.status_code == status.HTTP_200_OK
        assert "access_token" in new_login.json()
        assert "seed" not in new_login.json()

    def test_seed_not_exposed_in_login_or_me_response(self, client):
        """Neither /auth/login nor /auth/me may expose the recovery seed."""
        username = "seed_privacy_user"
        password = "SecurePassword123!"

        reg_res = client.post(
            "/api/v1/auth/register",
            json={"username": username, "password": password},
        )
        assert reg_res.status_code == status.HTTP_201_CREATED

        # Check login response
        login_res = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )
        assert login_res.status_code == status.HTTP_200_OK
        login_data = login_res.json()
        assert "seed" not in login_data
        token = login_data["access_token"]

        # Check /me response
        me_res = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me_res.status_code == status.HTTP_200_OK
        me_data = me_res.json()
        assert "seed" not in me_data
        assert "password_hash" not in me_data


