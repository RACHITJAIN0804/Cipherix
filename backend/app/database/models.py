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


class Base(DeclarativeBase):
    pass


class Vault(Base):
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
    processing_status: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True, default=None
    )
    extraction_version: Mapped[Optional[str]] = mapped_column(
        String(16), nullable=True, default=None
    )
    chunking_version: Mapped[Optional[str]] = mapped_column(
        String(16), nullable=True, default=None
    )
    chunk_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, default=None)
    processed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
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

    vault: Mapped["Vault"] = relationship("Vault", back_populates="documents")

    def __repr__(self) -> str:
        return (
            f"<Document id={self.id!r} vault_id={self.vault_id!r} "
            f"filename={self.original_filename!r}>"
        )


class SecurityMetadata(Base):
    __tablename__ = "security_metadata"

    vault_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("vaults.id", ondelete="CASCADE"),
        primary_key=True,
    )

    key_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1"
    )
    encryption_algorithm: Mapped[str] = mapped_column(
        String(32), nullable=False, default="AES-256-GCM"
    )

    encrypted_vault_key: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)

    salt: Mapped[str] = mapped_column(String(128), nullable=False)
    argon2_time_cost: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    argon2_memory_cost: Mapped[int] = mapped_column(
        Integer, nullable=False, default=65536
    )
    argon2_parallelism: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    argon2_hash_len: Mapped[int] = mapped_column(Integer, nullable=False, default=32)

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

    vault: Mapped["Vault"] = relationship(
        "Vault", back_populates="security_metadata"
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityMetadata vault_id={self.vault_id!r} "
            f"algorithm={self.encryption_algorithm!r}>"
        )


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("username", name="uq_users_username"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
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

    vaults: Mapped[list["Vault"]] = relationship(
        "Vault",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )
    computer_access: Mapped[Optional["UserComputerAccess"]] = relationship(
        "UserComputerAccess",
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
        lazy="select",
    )

    def __repr__(self) -> str:
        return (
            f"<User id={self.id!r} username={self.username!r} "
            f"is_active={self.is_active!r}>"
        )


class UserComputerAccess(Base):
    __tablename__ = "user_computer_access"

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
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

    user: Mapped["User"] = relationship("User", back_populates="computer_access")

    def __repr__(self) -> str:
        return f"<UserComputerAccess user_id={self.user_id!r} enabled={self.enabled!r}>"


class ComputerAccessApproval(Base):
    __tablename__ = "computer_access_approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    parameters_json: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
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
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<ComputerAccessApproval id={self.id!r} user_id={self.user_id!r} action={self.action!r} status={self.status!r}>"


class ComputerAccessAuditLog(Base):
    __tablename__ = "computer_access_audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vault_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("vaults.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    relative_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    result_status: Mapped[str] = mapped_column(String(32), nullable=False)
    approval_status: Mapped[str] = mapped_column(String(32), nullable=False)
    details_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    def __repr__(self) -> str:
        return (
            f"<ComputerAccessAuditLog id={self.id!r} user_id={self.user_id!r} "
            f"action={self.action!r} result={self.result_status!r}>"
        )


class BlockchainAnchorRecord(Base):
    __tablename__ = "blockchain_anchor_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    document_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("documents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    privacy_reference: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    integrity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    network: Mapped[str] = mapped_column(
        String(64), nullable=False, default="local-development"
    )
    tx_hash: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    block_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="anchored"
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

    def __repr__(self) -> str:
        return (
            f"<BlockchainAnchorRecord id={self.id!r} doc_id={self.document_id!r} "
            f"network={self.network!r} status={self.status!r}>"
        )
