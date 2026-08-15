"""
tests/test_search.py
---------------------
End-to-end Integration tests for Semantic Search & Vault Security Isolation.
"""

import io
import pytest
from fastapi import status
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import create_app



@pytest.fixture(scope="function")
def in_memory_engine(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "VAULT_DIR", tmp_path / "vaults")
    monkeypatch.setattr(settings, "VECTOR_DB_DIR", tmp_path / "vector_db")
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
    app = create_app()

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    from app.database import get_db
    app.dependency_overrides[get_db] = _override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def _register_and_login(client: TestClient, username: str, password: str) -> dict[str, str]:
    reg_res = client.post("/api/v1/auth/register", json={"username": username, "password": password})
    assert reg_res.status_code == status.HTTP_201_CREATED

    login_res = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert login_res.status_code == status.HTTP_200_OK
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestSemanticSearch:

    def test_search_successful_workflow(self, client):
        pwd = "Password123!"
        headers = _register_and_login(client, "search_user1", pwd)

        # 1. Create Vault & Unlock
        v_res = client.post("/api/v1/vaults/", headers=headers, json={"name": "Search Vault", "password": pwd})
        assert v_res.status_code == status.HTTP_201_CREATED
        v_id = v_res.json()["vault_id"]
        client.post(f"/api/v1/vaults/{v_id}/unlock", headers=headers)

        # 2. Upload Document
        doc_text = "Cipherix stores encrypted files and uses Argon2id for key derivation."
        d_res = client.post(
            f"/api/v1/vaults/{v_id}/documents",
            headers={**headers, "X-Vault-Password": pwd},
            files={"file": ("sec.txt", io.BytesIO(doc_text.encode("utf-8")), "text/plain")},
        )
        assert d_res.status_code == status.HTTP_201_CREATED
        d_id = d_res.json()["document_id"]

        # 3. Process Document
        p_res = client.post(
            f"/api/v1/vaults/{v_id}/documents/{d_id}/process",
            headers={**headers, "X-Vault-Password": pwd},
        )
        assert p_res.status_code == status.HTTP_200_OK
        assert p_res.json()["processing_status"] == "processed"

        # 4. Perform Search
        s_res = client.post(
            "/api/v1/search",
            headers=headers,
            json={"vault_id": v_id, "query": "Argon2id key derivation", "top_k": 3},
        )
        assert s_res.status_code == status.HTTP_200_OK
        s_data = s_res.json()
        assert s_data["vault_id"] == v_id
        assert s_data["total_results"] > 0
        assert s_data["results"][0]["document_id"] == d_id
        assert s_data["results"][0]["original_filename"] == "sec.txt"
        assert "Argon2id" in s_data["results"][0]["text"]

    def test_vault_security_isolation_user_a_cannot_search_user_b_vault(self, client):
        pwd = "Password123!"
        headers_a = _register_and_login(client, "user_a", pwd)
        headers_b = _register_and_login(client, "user_b", pwd)

        # User A creates Vault A
        v_res = client.post("/api/v1/vaults/", headers=headers_a, json={"name": "User A Vault", "password": pwd})
        v_id_a = v_res.json()["vault_id"]
        client.post(f"/api/v1/vaults/{v_id_a}/unlock", headers=headers_a)

        # User A uploads & processes document
        d_res = client.post(
            f"/api/v1/vaults/{v_id_a}/documents",
            headers={**headers_a, "X-Vault-Password": pwd},
            files={"file": ("a.txt", io.BytesIO(b"User A sensitive financial records"), "text/plain")},
        )
        d_id = d_res.json()["document_id"]
        client.post(f"/api/v1/vaults/{v_id_a}/documents/{d_id}/process", headers={**headers_a, "X-Vault-Password": pwd})

        # User B attempts to search User A's vault
        s_res = client.post(
            "/api/v1/search",
            headers=headers_b,
            json={"vault_id": v_id_a, "query": "financial records"},
        )
        assert s_res.status_code == status.HTTP_403_FORBIDDEN

    def test_document_deletion_removes_search_vectors(self, client):
        pwd = "Password123!"
        headers = _register_and_login(client, "del_doc_user", pwd)

        v_res = client.post("/api/v1/vaults/", headers=headers, json={"name": "Del Doc Vault", "password": pwd})
        v_id = v_res.json()["vault_id"]
        client.post(f"/api/v1/vaults/{v_id}/unlock", headers=headers)

        d_res = client.post(
            f"/api/v1/vaults/{v_id}/documents",
            headers={**headers, "X-Vault-Password": pwd},
            files={"file": ("temporary.txt", io.BytesIO(b"Temporary data to delete"), "text/plain")},
        )
        d_id = d_res.json()["document_id"]
        client.post(f"/api/v1/vaults/{v_id}/documents/{d_id}/process", headers={**headers, "X-Vault-Password": pwd})

        # Verify search returns result before deletion
        s1 = client.post("/api/v1/search", headers=headers, json={"vault_id": v_id, "query": "Temporary data"})
        assert s1.json()["total_results"] > 0

        # Delete document
        del_res = client.delete(f"/api/v1/vaults/{v_id}/documents/{d_id}", headers=headers)
        assert del_res.status_code == status.HTTP_204_NO_CONTENT

        # Search should now return 0 results
        s2 = client.post("/api/v1/search", headers=headers, json={"vault_id": v_id, "query": "Temporary data"})
        assert s2.json()["total_results"] == 0

    def test_vault_deletion_removes_all_vectors(self, client):
        pwd = "Password123!"
        headers = _register_and_login(client, "del_vault_user", pwd)

        v_res = client.post("/api/v1/vaults/", headers=headers, json={"name": "Del Vault", "password": pwd})
        v_id = v_res.json()["vault_id"]
        client.post(f"/api/v1/vaults/{v_id}/unlock", headers=headers)

        d_res = client.post(
            f"/api/v1/vaults/{v_id}/documents",
            headers={**headers, "X-Vault-Password": pwd},
            files={"file": ("v_doc.txt", io.BytesIO(b"Vault content"), "text/plain")},
        )
        d_id = d_res.json()["document_id"]
        client.post(f"/api/v1/vaults/{v_id}/documents/{d_id}/process", headers={**headers, "X-Vault-Password": pwd})

        # Delete Vault
        del_res = client.delete(f"/api/v1/vaults/{v_id}", headers=headers)
        assert del_res.status_code == status.HTTP_204_NO_CONTENT

        # Attempt search on deleted vault
        s_res = client.post("/api/v1/search", headers=headers, json={"vault_id": v_id, "query": "Vault content"})
        assert s_res.status_code in (status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN)

    def test_reindexing_prevents_duplicate_vectors(self, client):
        pwd = "Password123!"
        headers = _register_and_login(client, "reindex_user", pwd)

        v_res = client.post("/api/v1/vaults/", headers=headers, json={"name": "Reindex Vault", "password": pwd})
        v_id = v_res.json()["vault_id"]
        client.post(f"/api/v1/vaults/{v_id}/unlock", headers=headers)

        d_res = client.post(
            f"/api/v1/vaults/{v_id}/documents",
            headers={**headers, "X-Vault-Password": pwd},
            files={"file": ("r.txt", io.BytesIO(b"Unique reindexing content test string"), "text/plain")},
        )
        d_id = d_res.json()["document_id"]

        # Process document twice
        client.post(f"/api/v1/vaults/{v_id}/documents/{d_id}/process", headers={**headers, "X-Vault-Password": pwd})
        client.post(f"/api/v1/vaults/{v_id}/documents/{d_id}/process", headers={**headers, "X-Vault-Password": pwd})

        # Search should return exact chunk count, no duplicates
        s_res = client.post("/api/v1/search", headers=headers, json={"vault_id": v_id, "query": "Unique reindexing"})
        assert s_res.json()["total_results"] == 1

    def test_empty_query_handling(self, client):
        pwd = "Password123!"
        headers = _register_and_login(client, "empty_q_user", pwd)

        v_res = client.post("/api/v1/vaults/", headers=headers, json={"name": "Empty Q Vault", "password": pwd})
        v_id = v_res.json()["vault_id"]

        s_res = client.post("/api/v1/search", headers=headers, json={"vault_id": v_id, "query": "   "})
        assert s_res.status_code == status.HTTP_200_OK
        assert s_res.json()["total_results"] == 0
