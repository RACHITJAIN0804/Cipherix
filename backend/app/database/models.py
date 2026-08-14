"""
database/models.py
------------------
SQLAlchemy ORM models for Cipherix application metadata.

SQLite stores ONLY application metadata — never plaintext passwords,
Master Keys, plaintext Vault Keys, plaintext recovery seeds, or document
contents.

Data separation
---------------
* Encrypted document blobs  → filesystem  (``vaults/<id>/encrypted/*.bin``)
* JSON metadata sidecars     → filesystem  (``vaults/<id>/metadata/*.json``)
* Application metadata index → SQLite      (this module)

What IS stored here (safe to persist)
--------------------------------------
* Vault names, status, and algorithm version labels
* Document filenames, MIME types, plaintext sizes, encrypted paths
* Ciphertext of the wrapped Vault Key (Base64 AES-256-GCM output)
* Nonce for AES-GCM decryption (not secret — required for decryption)
* Argon2id salt (not secret — required for key re-derivation)
* Argon2id KDF parameters (public algorithm parameters)
* Recovery seed fingerprint (first 16 hex chars of SHA-256 — cannot
  reconstruct the seed)

What is NEVER stored here
--------------------------
* Passwords (in any form)
* Master Keys (ephemeral, discarded in ``finally`` blocks)
* Plaintext Vault Keys (discarded before any DB call)
* Plaintext recovery seeds (shown once in API response, never persisted)
* Document contents (encrypted blobs stay on the filesystem only)

Relationships
-------------
Vault
 ├── documents  (one-to-many, CASCADE DELETE)
 └── security_metadata  (one-to-one, CASCADE DELETE)
"""

from datetime import UTC, datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# ---------------------------------------------------------------------------
# Declarative base
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Shared declarative base for all Cipherix ORM models."""


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class Vault(Base):
    """
    Application metadata record for a Cipherix vault.

    One row exists per vault.  The vault UUID is the primary key — the same
    UUID used as the filesystem directory name, so the two layers stay
    perfectly correlated.

    Attributes
    ----------
    id:
        UUID4 string — matches the vault directory name under ``vaults/``.
    name:
        Human-readable vault name supplied at creation time.
    status:
        Lock state: ``"locked"`` or ``"unlocked"``.  Mirrors the value
        written to ``manifest.json`` on disk.
    security_version:
        Schema version of the security metadata for this vault.
    created_at:
        UTC timestamp set once at creation; never updated.
    updated_at:
        UTC timestamp updated on every status change.
    documents:
        Back-populated list of :class:`Document` rows belonging to this vault.
    security_metadata:
        Back-populated :class:`SecurityMetadata` row (one-to-one).
    """

    __tablename__ = "vaults"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="locked", index=True
    )
    security_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="vaults",
    )
    documents: Mapped[list["Document"]] = relationship(
        "Document",
        back_populates="vault",
        cascade="all, delete-orphan",
        lazy="select",
    )
    security_metadata: Mapped[Optional["SecurityMetadata"]] = relationship(
        "SecurityMetadata",
        back_populates="vault",
        cascade="all, delete-orphan",
        uselist=False,
        lazy="select",
    )

    def __repr__(self) -> str:
        return (
            f"<Vault id={self.id!r} name={self.name!r} status={self.status!r}>"
        )


class Document(Base):
    """
    Application metadata record for an encrypted document inside a vault.

    One row exists per document upload.  The document UUID is the primary
    key — the same UUID used as the filename stem of the ``.bin`` blob and
    the ``.json`` sidecar on disk.

    Document contents are NEVER stored in this table.  Only metadata
    needed for listing, routing, and integrity verification is recorded.

    Attributes
    ----------
    id:
        UUID4 string — matches ``encrypted/<id>.bin`` and
        ``metadata/<id>.json`` on disk.
    vault_id:
        Foreign key to :class:`Vault`.  Every document belongs to exactly
        one vault.  Deleting the parent vault cascades to all its documents.
    original_filename:
        Sanitised filename as supplied by the client at upload time.
    mime_type:
        MIME type from the ``Content-Type`` part header (or
        ``"application/octet-stream"`` when absent).
    size:
        **Plaintext** byte length of the original file before encryption.
        The on-disk ``.bin`` blob is slightly larger (AES-GCM auth tag).
    encrypted_path:
        Relative path from the vault root to the ``.bin`` blob,
        e.g. ``encrypted/<id>.bin``.  Stored as a relative string so the
        record remains correct if the ``vaults/`` base directory is moved.
    integrity_hash:
        Lowercase hex SHA-256 digest of the **ciphertext** blob, computed
        immediately after AES-256-GCM encryption.  ``None`` for documents
        uploaded before integrity verification was introduced.
    encryption_version:
        Algorithm/version label (e.g. ``"AES-256-GCM-v1"``).
    created_at:
        UTC timestamp set once when the document record is first inserted.
    updated_at:
        UTC timestamp updated if the document metadata changes.
    vault:
        Back-populated :class:`Vault` parent row.
    """

    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    vault_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("vaults.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(255), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    encrypted_path: Mapped[str] = mapped_column(String(512), nullable=False)
    integrity_hash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    encryption_version: Mapped[str] = mapped_column(
        String(64), nullable=False, default="AES-256-GCM-v1"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    vault: Mapped["Vault"] = relationship("Vault", back_populates="documents")

    def __repr__(self) -> str:
        return (
            f"<Document id={self.id!r} vault_id={self.vault_id!r} "
            f"filename={self.original_filename!r}>"
        )


class SecurityMetadata(Base):
    """
    Cryptographic metadata for a vault's key-management scheme.

    One row exists per vault (one-to-one with :class:`Vault`).  This table
    mirrors the information spread across ``key.json``, ``password_meta.json``,
    and ``recovery_meta.json`` on disk — providing a single queryable
    location for algorithm negotiation and recovery configuration.

    Security guarantees
    -------------------
    * ``encrypted_vault_key`` stores **ciphertext** (Base64 AES-256-GCM
      output) — NEVER the plaintext Vault Key.
    * ``nonce`` stores the 12-byte AES-GCM nonce (Base64) required for
      decryption — not a secret, but required alongside the key.
    * ``salt`` stores the per-vault Argon2id salt (hex) used during Master
      Key derivation — not a secret, but required for re-derivation.
    * ``seed_fingerprint`` stores the first 16 hex characters of
      SHA-256(seed) — a partial hash that cannot reconstruct the seed.
    * Passwords, Master Keys, and plaintext seeds are NEVER stored.

    Attributes
    ----------
    vault_id:
        UUID4 string — primary key and foreign key to :class:`Vault`.
    key_version:
        Schema version of the key record (mirrors ``key.json``).
    encryption_algorithm:
        Symmetric cipher label, e.g. ``"AES-256-GCM"``.
    encrypted_vault_key:
        Base64-encoded AES-256-GCM ciphertext of the Vault Key.
        This is the wrapped form — the plaintext Vault Key is NEVER stored.
    nonce:
        Base64-encoded 12-byte AES-GCM nonce used when encrypting the
        Vault Key.  Required for decryption; not a secret.
    salt:
        Hex-encoded per-vault Argon2id salt.  Required to re-derive the
        Master Key at unlock time.  Not a secret.
    argon2_time_cost:
        Argon2id iteration count stored for future key re-derivation.
    argon2_memory_cost:
        Argon2id memory cost in KiB stored for future key re-derivation.
    argon2_parallelism:
        Argon2id thread count stored for future key re-derivation.
    argon2_hash_len:
        Argon2id output key length in bytes.
    recovery_version:
        Schema version of the recovery metadata (``None`` if no seed
        has been generated yet).
    seed_fingerprint:
        First 16 hex characters of SHA-256(recovery_seed).  ``None`` if
        no recovery seed has been generated.  Cannot reconstruct the seed.
    created_at:
        UTC timestamp set once when the security metadata record is created.
    updated_at:
        UTC timestamp updated on every password change or recovery-seed
        regeneration.
    vault:
        Back-populated parent :class:`Vault` row.
    """

    __tablename__ = "security_metadata"

    # Primary key is also the FK — one-to-one with Vault.
    vault_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("vaults.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # Key metadata (mirrors key.json)
    key_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1"
    )
    encryption_algorithm: Mapped[str] = mapped_column(
        String(32), nullable=False, default="AES-256-GCM"
    )

    # Wrapped Vault Key envelope — CIPHERTEXT ONLY, never plaintext.
    encrypted_vault_key: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)

    # Argon2id parameters (mirrors password_meta.json)
    # salt is not a secret; it is required to reproduce the Master Key derivation.
    salt: Mapped[str] = mapped_column(String(128), nullable=False)
    argon2_time_cost: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    argon2_memory_cost: Mapped[int] = mapped_column(
        Integer, nullable=False, default=65536
    )
    argon2_parallelism: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    argon2_hash_len: Mapped[int] = mapped_column(Integer, nullable=False, default=32)

    # Recovery seed metadata (mirrors recovery_meta.json — populated later)
    # seed_fingerprint is the first 16 hex chars of SHA-256(seed).
    # It CANNOT reconstruct the seed and is safe to store.
    recovery_version: Mapped[Optional[str]] = mapped_column(
        String(16), nullable=True, default=None
    )
    seed_fingerprint: Mapped[Optional[str]] = mapped_column(
        String(16), nullable=True, default=None
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    vault: Mapped["Vault"] = relationship(
        "Vault", back_populates="security_metadata"
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityMetadata vault_id={self.vault_id!r} "
            f"algorithm={self.encryption_algorithm!r}>"
        )


class User(Base):
    """
    Application user account record.

    One row exists per registered user.  The user UUID is the ``sub`` claim
    in issued JWTs, so it is stable even if the username changes.

    Security guarantees
    -------------------
    * ``password_hash`` stores the Argon2id hash produced by
      ``argon2.PasswordHasher`` — **never** the plaintext password.
    * JWT tokens are **not** stored here; they are stateless.
    * The ``is_active`` flag allows soft-deactivation without deleting the
      row (preserves audit trails and foreign-key integrity).

    Attributes
    ----------
    id:
        UUID4 string — used as the ``sub`` claim in JWTs.
    username:
        Unique login identifier chosen at registration (3–64 characters).
        Unique constraint enforced at both the service layer and the DB.
    password_hash:
        Argon2id hash of the user's password.  Never the plaintext password.
    is_active:
        ``True`` by default.  Set to ``False`` to deactivate the account
        without deleting the row.  Inactive users cannot log in.
    created_at:
        UTC timestamp set once at registration; never updated.
    updated_at:
        UTC timestamp updated on every profile or password change.
    """

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("username", name="uq_users_username"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    # Argon2id hash — NEVER the plaintext password.
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    vaults: Mapped[list["Vault"]] = relationship(
        "Vault",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def __repr__(self) -> str:
        return (
            f"<User id={self.id!r} username={self.username!r} "
            f"is_active={self.is_active!r}>"
        )
