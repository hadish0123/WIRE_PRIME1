"""OpenVPN client records

Revision ID: 0022
Revises: 0021
"""

import sqlalchemy as sa
from alembic import op

revision = '0022'
down_revision = '0021'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        'openvpn_clients',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('user_id', sa.String(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('node_id', sa.String(), sa.ForeignKey('nodes.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('node_id', 'name', name='uq_openvpn_client_node_name'),
    )
    op.create_index('ix_openvpn_clients_user_id', 'openvpn_clients', ['user_id'])
    op.create_index('ix_openvpn_clients_node_id', 'openvpn_clients', ['node_id'])

def downgrade() -> None:
    op.drop_index('ix_openvpn_clients_node_id', table_name='openvpn_clients')
    op.drop_index('ix_openvpn_clients_user_id', table_name='openvpn_clients')
    op.drop_table('openvpn_clients')
