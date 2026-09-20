from alembic import op
import sqlalchemy as sa
revision="105_agent_url";down_revision="104_wg_server_key";branch_labels=None;depends_on=None
def upgrade():
 if "agent_url" not in {x["name"] for x in sa.inspect(op.get_bind()).get_columns("nodes")}:op.add_column("nodes",sa.Column("agent_url",sa.String(512),nullable=True))
def downgrade():
 if "agent_url" in {x["name"] for x in sa.inspect(op.get_bind()).get_columns("nodes")}:op.drop_column("nodes","agent_url")
