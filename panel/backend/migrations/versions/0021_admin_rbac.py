"""database-backed admin accounts and RBAC metadata

Revision ID: 0021
Revises: 0020
"""

import sqlalchemy as sa
from alembic import op

revision = '0021'
down_revision = '0020'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        'admins',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('username', sa.String(), nullable=False),
        sa.Column('password_hash', sa.Text(), nullable=False),
        sa.Column('role', sa.String(), nullable=False, server_default='sub_admin'),
        sa.Column('permissions_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('node_ids_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('username', name='uq_admins_username'),
    )
    op.create_index('ix_admins_username', 'admins', ['username'], unique=True)

def downgrade() -> None:
    op.drop_index('ix_admins_username', table_name='admins')
    op.drop_table('admins')
