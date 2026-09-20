from alembic import op
import sqlalchemy as sa
revision="106_peer_counters"
down_revision="105_agent_url"
branch_labels=None
depends_on=None
def upgrade():
 op.create_table("node_peer_counters",
  sa.Column("id",sa.String(36),primary_key=True),
  sa.Column("tenant_id",sa.String(36),sa.ForeignKey("tenants.id",ondelete="CASCADE"),nullable=False),
  sa.Column("node_id",sa.String(36),sa.ForeignKey("nodes.id",ondelete="CASCADE"),nullable=False),
  sa.Column("inbound_id",sa.String(36),sa.ForeignKey("inbounds.id",ondelete="CASCADE"),nullable=False),
  sa.Column("client_id",sa.String(36),sa.ForeignKey("clients.id",ondelete="CASCADE"),nullable=False),
  sa.Column("public_identifier",sa.String(255),nullable=False),
  sa.Column("bytes_in",sa.BigInteger(),nullable=False,server_default="0"),
  sa.Column("bytes_out",sa.BigInteger(),nullable=False,server_default="0"),
  sa.Column("updated_at",sa.DateTime(timezone=True),nullable=False))
 op.create_unique_constraint("uq_node_peer_counter","node_peer_counters",["node_id","inbound_id","public_identifier"])
def downgrade():op.drop_table("node_peer_counters")
