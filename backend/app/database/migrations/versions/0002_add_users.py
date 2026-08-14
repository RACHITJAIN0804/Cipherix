"""Add users table for JWT authentication.

Revision ID: 0002_add_users
Revises: 0001_initial
Create Date: 2026-08-14 00:00:00.000000 UTC

Creates the ``users`` table required for JWT-based authentication:

* ``id``            — UUID4 primary key (also the JWT ``sub`` claim)
* ``username``      — unique login identifier (3–64 chars)
* ``password_hash`` — Argon2id hash (NEVER plaintext password)
* ``is_active``     — soft-deactivation flag
* ``created_at``    — UTC creation timestamp
* ``updated_at``    — UTC last-modified timestamp

Security guarantees
-------------------
* No plaintext passwords are ever stored.
* JWT tokens are NOT stored in the database (stateless).
* The unique constraint on ``username`` is enforced at both the service
  layer and the database level.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_add_users"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("username", sa.String(64), nullable=False),
        # Argon2id hash — NEVER the plaintext password.
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
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
        sa.UniqueConstraint("username", name="uq_users_username"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")
