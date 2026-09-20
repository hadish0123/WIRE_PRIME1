from alembic import op
import sqlalchemy as sa
revision="104_wg_server_key";down_revision="103_openvpn_ca";branch_labels=None;depends_on=None
def upgrade():
 if "server_private_key_encrypted" not in {x["name"] for x in sa.inspect(op.get_bind()).get_columns("inbound_wireguard")}:op.add_column("inbound_wireguard",sa.Column("server_private_key_encrypted",sa.Text(),nullable=True))
def downgrade():
 if "server_private_key_encrypted" in {x["name"] for x in sa.inspect(op.get_bind()).get_columns("inbound_wireguard")}:op.drop_column("server_private_key_encrypted")
