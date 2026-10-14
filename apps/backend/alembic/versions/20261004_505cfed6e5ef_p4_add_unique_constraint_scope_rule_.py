"""p4_add_unique_constraint_scope_rule_order_and_target_type_not_null

Revision ID: 505cfed6e5ef
Revises: af69e75f099e
Create Date: 2026-10-04 22:29:00.976292
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '505cfed6e5ef'
down_revision = 'af69e75f099e'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add unique constraint on scope_id + order for scope_rules
    op.create_unique_constraint('scope_rule_order', 'scope_rules', ['scope_id', 'order'])
    
    # Alter target_type column to use native enum and be not nullable
    # First, update any NULL values to a default (DOMAIN)
    op.execute("UPDATE targets SET target_type = 'domain' WHERE target_type IS NULL")
    
    # Then alter the column with explicit cast
    op.alter_column('targets', 'target_type',
               existing_type=sa.VARCHAR(length=64),
               type_=sa.Enum('domain', 'subdomain_pattern', 'ip', 'cidr', 'url', 'api', 'apk', 'other', name='scoperuletargettype'),
               nullable=False,
               postgresql_using="target_type::scoperuletargettype")


def downgrade() -> None:
    # Drop unique constraint
    op.drop_constraint('scope_rule_order', 'scope_rules', type_='unique')
    
    # Revert target_type column
    op.alter_column('targets', 'target_type',
               existing_type=sa.Enum('domain', 'subdomain_pattern', 'ip', 'cidr', 'url', 'api', 'apk', 'other', name='scoperuletargettype'),
               type_=sa.VARCHAR(length=64),
               nullable=True)