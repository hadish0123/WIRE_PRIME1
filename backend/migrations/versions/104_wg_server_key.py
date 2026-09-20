from alembic import op
import sqlalchemy as sa
revision="104_wg_server_key"
down_revision="103_openvpn_ca"
branch_labels=None
depends_on=None
def upgrade():op.add_column("inbound_wireguard",sa.Column("server_private_key_encrypted",sa.Text(),nullable=True))
def downgrade():op.drop_column("inbound_wireguard","server_private_key_encrypted")
