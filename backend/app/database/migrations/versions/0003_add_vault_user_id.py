
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


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
