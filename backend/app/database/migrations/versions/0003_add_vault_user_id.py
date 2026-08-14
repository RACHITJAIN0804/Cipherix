"""Add user_id foreign key to vaults table for vault ownership.

Revision ID: 0003_add_vault_user_id
Revises: 0002_add_users
Create Date: 2026-08-14 00:00:00.000000 UTC

Adds the ``user_id`` column to the ``vaults`` table to enforce vault ownership:

* ``user_id`` — UUID4 foreign key to ``users.id`` (CASCADE DELETE)
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_add_vault_user_id"
down_revision: Union[str, None] = "0002_add_users"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vaults",
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )
    op.create_index("ix_vaults_user_id", "vaults", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_vaults_user_id", table_name="vaults")
    op.drop_column("vaults", "user_id")
