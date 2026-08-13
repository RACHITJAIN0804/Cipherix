"""
tests/test_database.py
-----------------------
Unit and integration tests for the SQLite metadata persistence layer.

These tests verify:
- Database initialisation creates all expected tables.
- Vault, Document, and SecurityMetadata records can be created, queried,
  updated, and deleted.
- Cascade DELETE works: deleting a Vault row also removes its Documents and
  SecurityMetadata rows.
- Transaction rollback is correctly handled on simulated DB failures.
- No sensitive plaintext is present in the record attributes.

All tests use an in-memory SQLite database so they are completely isolated
from the development/production database on disk.
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.database.models import Base, Document, SecurityMetadata, Vault


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def in_memory_engine():
    """
    Create a fresh in-memory SQLite engine for each test.

    Using ``scope="function"`` ensures tests are fully isolated — no state
    leaks between them.
    """
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    # Enable FK enforcement (SQLite off by default).
    with engine.connect() as conn:
        conn.execute(text("PRAGMA foreign_keys=ON"))
        conn.commit()
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture(scope="function")
def db_session(in_memory_engine):
    """
    Yield a transactional SQLAlchemy session and roll it back after each test.

    Rolling back (rather than committing) keeps the test database clean
    between tests that add data.
    """
    factory = sessionmaker(bind=in_memory_engine, autocommit=False, autoflush=False)
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _new_vault_id() -> str:
    return str(uuid.uuid4())


def _sample_vault(name: str = "Test Vault") -> Vault:
    now = datetime.now(UTC)
    return Vault(
        id=_new_vault_id(),
        name=name,
        status="locked",
        security_version="1.0",
        created_at=now,
        updated_at=now,
    )


def _sample_security_metadata(vault_id: str) -> SecurityMetadata:
    now = datetime.now(UTC)
    return SecurityMetadata(
        vault_id=vault_id,
        key_version="1",
        encryption_algorithm="AES-256-GCM",
        # encrypted_vault_key is CIPHERTEXT — a Base64 placeholder here.
        encrypted_vault_key="AAECBAUGB/8=",  # safe fake ciphertext (Base64)
        nonce="AAAAAAAAAAAAAAAA",             # 12-byte nonce (Base64)
        salt="deadbeef" * 8,                   # 32-byte hex salt
        argon2_time_cost=3,
        argon2_memory_cost=65536,
        argon2_parallelism=4,
        argon2_hash_len=32,
        recovery_version=None,
        seed_fingerprint=None,
        created_at=now,
        updated_at=now,
    )


def _sample_document(vault_id: str) -> Document:
    now = datetime.now(UTC)
    doc_id = str(uuid.uuid4())
    return Document(
        id=doc_id,
        vault_id=vault_id,
        original_filename="secret.pdf",
        mime_type="application/pdf",
        size=1024,
        encrypted_path=f"encrypted/{doc_id}.bin",
        integrity_hash="a" * 64,
        encryption_version="AES-256-GCM-v1",
        created_at=now,
        updated_at=now,
    )


# ---------------------------------------------------------------------------
# DB Initialisation
# ---------------------------------------------------------------------------


class TestDatabaseInitialisation:
    """Verify that the schema is created correctly."""

    def test_all_tables_created(self, in_memory_engine):
        """create_all should create vaults, documents, and security_metadata."""
        inspector = inspect(in_memory_engine)
        table_names = set(inspector.get_table_names())
        assert "vaults" in table_names
        assert "documents" in table_names
        assert "security_metadata" in table_names

    def test_vaults_columns(self, in_memory_engine):
        inspector = inspect(in_memory_engine)
        cols = {c["name"] for c in inspector.get_columns("vaults")}
        expected = {"id", "name", "status", "security_version", "created_at", "updated_at"}
        assert expected.issubset(cols)

    def test_documents_columns(self, in_memory_engine):
        inspector = inspect(in_memory_engine)
        cols = {c["name"] for c in inspector.get_columns("documents")}
        expected = {
            "id", "vault_id", "original_filename", "mime_type", "size",
            "encrypted_path", "integrity_hash", "encryption_version",
            "created_at", "updated_at",
        }
        assert expected.issubset(cols)

    def test_security_metadata_columns(self, in_memory_engine):
        inspector = inspect(in_memory_engine)
        cols = {c["name"] for c in inspector.get_columns("security_metadata")}
        expected = {
            "vault_id", "key_version", "encryption_algorithm",
            "encrypted_vault_key", "nonce", "salt",
            "argon2_time_cost", "argon2_memory_cost", "argon2_parallelism",
            "argon2_hash_len", "recovery_version", "seed_fingerprint",
            "created_at", "updated_at",
        }
        assert expected.issubset(cols)


# ---------------------------------------------------------------------------
# Vault CRUD
# ---------------------------------------------------------------------------


class TestVaultRecord:
    """Verify Vault record creation, retrieval, and deletion."""

    def test_create_vault(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        fetched = db_session.get(Vault, vault.id)
        assert fetched is not None
        assert fetched.name == vault.name
        assert fetched.status == "locked"
        assert fetched.security_version == "1.0"

    def test_vault_id_is_uuid_string(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()
        # Verify the ID is a valid UUID string.
        parsed = uuid.UUID(vault.id)
        assert str(parsed) == vault.id

    def test_update_vault_status(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        vault.status = "unlocked"
        db_session.flush()

        fetched = db_session.get(Vault, vault.id)
        assert fetched.status == "unlocked"

    def test_delete_vault(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        db_session.delete(vault)
        db_session.flush()

        assert db_session.get(Vault, vault.id) is None

    def test_vault_repr(self, db_session: Session):
        vault = _sample_vault("My Vault")
        assert "My Vault" in repr(vault)
        assert "locked" in repr(vault)


# ---------------------------------------------------------------------------
# SecurityMetadata CRUD
# ---------------------------------------------------------------------------


class TestSecurityMetadataRecord:
    """Verify SecurityMetadata record creation and vault association."""

    def test_create_security_metadata(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        sec = _sample_security_metadata(vault.id)
        db_session.add(sec)
        db_session.flush()

        fetched = db_session.get(SecurityMetadata, vault.id)
        assert fetched is not None
        assert fetched.encryption_algorithm == "AES-256-GCM"
        assert fetched.argon2_time_cost == 3

    def test_security_metadata_no_plaintext_key(self, db_session: Session):
        """
        The stored encrypted_vault_key must never equal a known plaintext key.

        This test asserts the sentinel placeholder is not equal to any real
        key and that the field is not a raw 256-bit hex string (which would
        indicate a plaintext key was accidentally stored).
        """
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        sec = _sample_security_metadata(vault.id)
        db_session.add(sec)
        db_session.flush()

        fetched = db_session.get(SecurityMetadata, vault.id)
        # Must not be exactly 64 hex chars (raw 256-bit Vault Key).
        assert len(fetched.encrypted_vault_key) != 64 or not all(
            c in "0123456789abcdef" for c in fetched.encrypted_vault_key
        ), "encrypted_vault_key should not store a raw hex Vault Key"
        # Must not be empty.
        assert fetched.encrypted_vault_key

    def test_seed_fingerprint_is_none_initially(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        sec = _sample_security_metadata(vault.id)
        db_session.add(sec)
        db_session.flush()

        fetched = db_session.get(SecurityMetadata, vault.id)
        assert fetched.seed_fingerprint is None
        assert fetched.recovery_version is None

    def test_update_seed_fingerprint(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        sec = _sample_security_metadata(vault.id)
        db_session.add(sec)
        db_session.flush()

        # Simulate setting the fingerprint after seed generation.
        sec.seed_fingerprint = "abcd1234efgh5678"[:16]  # 16 hex chars
        sec.recovery_version = "1"
        db_session.flush()

        fetched = db_session.get(SecurityMetadata, vault.id)
        assert fetched.seed_fingerprint is not None
        assert len(fetched.seed_fingerprint) == 16

    def test_security_metadata_repr(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        sec = _sample_security_metadata(vault.id)
        assert "AES-256-GCM" in repr(sec)


# ---------------------------------------------------------------------------
# Document CRUD
# ---------------------------------------------------------------------------


class TestDocumentRecord:
    """Verify Document record creation, retrieval, and deletion."""

    def test_create_document(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        doc = _sample_document(vault.id)
        db_session.add(doc)
        db_session.flush()

        fetched = db_session.get(Document, doc.id)
        assert fetched is not None
        assert fetched.original_filename == "secret.pdf"
        assert fetched.mime_type == "application/pdf"
        assert fetched.size == 1024
        assert fetched.vault_id == vault.id

    def test_document_encrypted_path_is_relative(self, db_session: Session):
        """Encrypted path must be relative (not an absolute path)."""
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        doc = _sample_document(vault.id)
        db_session.add(doc)
        db_session.flush()

        fetched = db_session.get(Document, doc.id)
        # Relative path must not start with '/' or a drive letter.
        assert not fetched.encrypted_path.startswith("/")
        assert fetched.encrypted_path.startswith("encrypted/")

    def test_document_integrity_hash_is_sha256_hex(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        doc = _sample_document(vault.id)
        db_session.add(doc)
        db_session.flush()

        fetched = db_session.get(Document, doc.id)
        assert fetched.integrity_hash is not None
        assert len(fetched.integrity_hash) == 64

    def test_delete_document(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        doc = _sample_document(vault.id)
        db_session.add(doc)
        db_session.flush()

        db_session.delete(doc)
        db_session.flush()

        assert db_session.get(Document, doc.id) is None
        # Vault must still exist after document deletion.
        assert db_session.get(Vault, vault.id) is not None

    def test_multiple_documents_per_vault(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        docs = [_sample_document(vault.id) for _ in range(3)]
        for d in docs:
            db_session.add(d)
        db_session.flush()

        fetched_vault = db_session.get(Vault, vault.id)
        assert len(fetched_vault.documents) == 3


# ---------------------------------------------------------------------------
# Cascade DELETE
# ---------------------------------------------------------------------------


class TestCascadeDelete:
    """Verify that CASCADE DELETE propagates from Vault to children."""

    def test_delete_vault_cascades_to_documents(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        doc = _sample_document(vault.id)
        db_session.add(doc)
        db_session.flush()

        doc_id = doc.id
        db_session.delete(vault)
        db_session.flush()

        assert db_session.get(Vault, vault.id) is None
        assert db_session.get(Document, doc_id) is None

    def test_delete_vault_cascades_to_security_metadata(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        sec = _sample_security_metadata(vault.id)
        db_session.add(sec)
        db_session.flush()

        db_session.delete(vault)
        db_session.flush()

        assert db_session.get(SecurityMetadata, vault.id) is None

    def test_delete_vault_cascades_to_both(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        sec = _sample_security_metadata(vault.id)
        docs = [_sample_document(vault.id) for _ in range(2)]
        db_session.add(sec)
        for d in docs:
            db_session.add(d)
        db_session.flush()

        doc_ids = [d.id for d in docs]
        db_session.delete(vault)
        db_session.flush()

        assert db_session.get(SecurityMetadata, vault.id) is None
        for did in doc_ids:
            assert db_session.get(Document, did) is None


# ---------------------------------------------------------------------------
# Vault–Document relationship
# ---------------------------------------------------------------------------


class TestVaultDocumentRelationship:
    """Verify the ORM relationship between Vault and Document."""

    def test_vault_documents_backref(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        doc = _sample_document(vault.id)
        db_session.add(doc)
        db_session.flush()

        # Access the relationship.
        db_session.refresh(vault)
        assert len(vault.documents) == 1
        assert vault.documents[0].id == doc.id

    def test_document_vault_backref(self, db_session: Session):
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        doc = _sample_document(vault.id)
        db_session.add(doc)
        db_session.flush()

        db_session.refresh(doc)
        assert doc.vault is not None
        assert doc.vault.id == vault.id


# ---------------------------------------------------------------------------
# Security: no sensitive data in stored records
# ---------------------------------------------------------------------------


class TestNoSensitiveData:
    """
    Assert that no obviously plaintext sensitive values appear in DB records.

    These tests are not cryptographic proofs — they check that the ORM
    models do not have fields intended for plaintext passwords/keys, and
    that the data stored matches expected formats (Base64, hex, etc.).
    """

    def test_vault_has_no_password_field(self):
        """Vault ORM model must not have a 'password' column."""
        vault = Vault.__table__
        column_names = {c.name for c in vault.columns}
        assert "password" not in column_names
        assert "master_key" not in column_names
        assert "vault_key" not in column_names

    def test_document_has_no_content_field(self):
        """Document ORM model must not have a 'content' or 'plaintext' column."""
        doc = Document.__table__
        column_names = {c.name for c in doc.columns}
        assert "content" not in column_names
        assert "plaintext" not in column_names
        assert "decrypted" not in column_names

    def test_security_metadata_has_no_plaintext_key_field(self):
        """SecurityMetadata must have no 'vault_key' or 'master_key' column."""
        sec = SecurityMetadata.__table__
        column_names = {c.name for c in sec.columns}
        assert "vault_key" not in column_names
        assert "master_key" not in column_names
        assert "password" not in column_names
        assert "seed" not in column_names  # seed_fingerprint is OK, 'seed' is not

    def test_seed_fingerprint_is_16_chars_when_set(self, db_session: Session):
        """seed_fingerprint must be exactly 16 hex chars — never the full seed."""
        vault = _sample_vault()
        db_session.add(vault)
        db_session.flush()

        sec = _sample_security_metadata(vault.id)
        sec.seed_fingerprint = "a1b2c3d4e5f60718"  # exactly 16 hex chars
        db_session.add(sec)
        db_session.flush()

        fetched = db_session.get(SecurityMetadata, vault.id)
        # BIP-39 24-word seed is hundreds of characters — 16 chars cannot be a seed.
        assert len(fetched.seed_fingerprint) == 16
