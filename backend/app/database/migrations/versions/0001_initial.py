"""Create initial tables: vaults, documents, security_metadata.

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-13 00:00:00.000000 UTC

Creates the three core tables that form the SQLite metadata persistence
layer for Cipherix:

* ``vaults``            — application metadata for each vault
* ``documents``         — metadata for encrypted documents (no content)
* ``security_metadata`` — cryptographic metadata (ciphertext, nonces, salts)

What is NOT stored (security guarantee)
---------------------------------------
* Passwords
* Master Keys
* Plaintext Vault Keys
* Plaintext recovery seeds
* Document contents
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vaults",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="locked"),
        sa.Column("security_version", sa.String(16), nullable=False, server_default="1.0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_vaults_name", "vaults", ["name"])
    op.create_index("ix_vaults_status", "vaults", ["status"])

    op.create_table(
        "documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "vault_id",
            sa.String(36),
            sa.ForeignKey("vaults.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("original_filename", sa.String(512), nullable=False),
        sa.Column("mime_type", sa.String(255), nullable=False),
        sa.Column("size", sa.Integer, nullable=False),
        sa.Column("encrypted_path", sa.String(512), nullable=False),
        sa.Column("integrity_hash", sa.String(64), nullable=True),
        sa.Column(
            "encryption_version",
            sa.String(64),
            nullable=False,
            server_default="AES-256-GCM-v1",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_documents_vault_id", "documents", ["vault_id"])

    op.create_table(
        "security_metadata",
        # Primary key is also the FK — one-to-one with vaults.
        sa.Column(
            "vault_id",
            sa.String(36),
            sa.ForeignKey("vaults.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("key_version", sa.String(16), nullable=False, server_default="1"),
        sa.Column(
            "encryption_algorithm",
            sa.String(32),
            nullable=False,
            server_default="AES-256-GCM",
        ),
        # Wrapped Vault Key ciphertext (Base64 AES-256-GCM output).
        # NEVER stores plaintext key material.
        sa.Column("encrypted_vault_key", sa.Text, nullable=False),
        sa.Column("nonce", sa.String(64), nullable=False),
        # Argon2id parameters (public — required to re-derive the Master Key).
        sa.Column("salt", sa.String(128), nullable=False),
        sa.Column("argon2_time_cost", sa.Integer, nullable=False, server_default="3"),
        sa.Column(
            "argon2_memory_cost", sa.Integer, nullable=False, server_default="65536"
        ),
        sa.Column(
            "argon2_parallelism", sa.Integer, nullable=False, server_default="4"
        ),
        sa.Column("argon2_hash_len", sa.Integer, nullable=False, server_default="32"),
        # Recovery seed metadata (populated after seed generation).
        # seed_fingerprint = first 16 hex chars of SHA-256(seed) — cannot
        # reconstruct the seed from this value.
        sa.Column("recovery_version", sa.String(16), nullable=True),
        sa.Column("seed_fingerprint", sa.String(16), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("security_metadata")
    op.drop_table("documents")
    op.drop_table("vaults")
