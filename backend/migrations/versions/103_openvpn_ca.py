from alembic import op
import sqlalchemy as sa
revision="103_openvpn_ca";down_revision="102_mfa";branch_labels=None;depends_on=None
def upgrade():
 if "ca_key_encrypted" not in {x["name"] for x in sa.inspect(op.get_bind()).get_columns("inbound_openvpn")}:op.add_column("inbound_openvpn",sa.Column("ca_key_encrypted",sa.Text(),nullable=True))
def downgrade():
 if "ca_key_encrypted" in {x["name"] for x in sa.inspect(op.get_bind()).get_columns("inbound_openvpn")}:op.drop_column("inbound_openvpn","ca_key_encrypted")
