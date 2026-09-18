"""
0004_blockchain_anchor_extended_fields.py

Adds three columns to blockchain_anchor_records that are required for full
document integrity tracking:

  vault_id                — vault reference for ownership queries without
                            joining through the documents table; nullable so
                            records created before this migration are preserved.

  last_verified_at        — UTC timestamp of the most recent verification call;
                            NULL until at least one verification has been run.

  last_verification_result — boolean result of the most recent verify_anchor
                             call: 1=matched, 0=not matched, NULL=never verified.

  error_message           — human-readable error from the most recent failed
                            blockchain operation; NULL when no error.

All columns are nullable / have server defaults so existing rows are
backward-compatible and no data migration is required.

Revision chain: 0003_add_vault_user_id -> 0004_blockchain_anchor_extended_fields
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0004_blockchain_anchor_extended_fields"
down_revision: Union[str, None] = "0003_add_vault_user_id"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # vault_id — soft reference; SET NULL on vault deletion so anchor history
    # is preserved even after a vault is removed.
    op.add_column(
        "blockchain_anchor_records",
        sa.Column(
            "vault_id",
            sa.String(36),
            sa.ForeignKey("vaults.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_blockchain_anchor_records_vault_id",
        "blockchain_anchor_records",
        ["vault_id"],
        unique=False,
    )

    # last_verified_at — set on every successful or failed verify call
    op.add_column(
        "blockchain_anchor_records",
        sa.Column(
            "last_verified_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # last_verification_result — True / False / None (never checked)
    op.add_column(
        "blockchain_anchor_records",
        sa.Column(
            "last_verification_result",
            sa.Boolean,
            nullable=True,
        ),
    )

    # error_message — last failure reason from anchor or verify operations
    op.add_column(
        "blockchain_anchor_records",
        sa.Column(
            "error_message",
            sa.Text,
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_blockchain_anchor_records_vault_id",
        table_name="blockchain_anchor_records",
    )
    op.drop_column("blockchain_anchor_records", "vault_id")
    op.drop_column("blockchain_anchor_records", "last_verified_at")
    op.drop_column("blockchain_anchor_records", "last_verification_result")
    op.drop_column("blockchain_anchor_records", "error_message")
