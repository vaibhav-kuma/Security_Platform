"""add_paused_scan_status

Revision ID: 552fc192c9bb
Revises: 392f4899e461
Create Date: 2026-10-02 22:11:02.201704
"""

from alembic import op

revision = '552fc192c9bb'
down_revision = '392f4899e461'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add 'paused' value to scan_status enum
    op.execute("ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'paused'")


def downgrade() -> None:
    # Note: Cannot easily remove enum values in PostgreSQL
    # This would require recreating the enum type
    pass