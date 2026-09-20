from alembic import op
import sqlalchemy as sa
revision="110_protocol_security";down_revision="109_commerce_rls";branch_labels=None;depends_on=None
def upgrade():
 insp=sa.inspect(op.get_bind())
 cols={x["name"] for x in insp.get_columns("inbound_wireguard")}
 adds={"amnezia_s1":sa.Column("amnezia_s1",sa.Integer(),nullable=False,server_default="80"),"amnezia_s2":sa.Column("amnezia_s2",sa.Integer(),nullable=False,server_default="120"),"amnezia_s3":sa.Column("amnezia_s3",sa.Integer(),nullable=False,server_default="0"),"amnezia_s4":sa.Column("amnezia_s4",sa.Integer(),nullable=False,server_default="0"),"amnezia_h1":sa.Column("amnezia_h1",sa.BigInteger(),nullable=False,server_default="123456789"),"amnezia_h2":sa.Column("amnezia_h2",sa.BigInteger(),nullable=False,server_default="223456789"),"amnezia_h3":sa.Column("amnezia_h3",sa.BigInteger(),nullable=False,server_default="323456789"),"amnezia_h4":sa.Column("amnezia_h4",sa.BigInteger(),nullable=False,server_default="423456789")}
 for name,col in adds.items():
  if name not in cols:op.add_column("inbound_wireguard",col)
 ocols={x["name"] for x in insp.get_columns("inbound_openvpn")}
 if "tls_crypt_key_encrypted" not in ocols:op.add_column("inbound_openvpn",sa.Column("tls_crypt_key_encrypted",sa.Text(),nullable=True))
def downgrade():
 for name in ["amnezia_h4","amnezia_h3","amnezia_h2","amnezia_h1","amnezia_s4","amnezia_s3","amnezia_s2","amnezia_s1"]:
  op.drop_column("inbound_wireguard",name)
 op.drop_column("inbound_openvpn","tls_crypt_key_encrypted")
