from alembic import op
import sqlalchemy as sa
revision="105_agent_url"
down_revision="104_wg_server_key"
branch_labels=None
depends_on=None
def upgrade():op.add_column("nodes",sa.Column("agent_url",sa.String(512),nullable=True))
def downgrade():op.drop_column("nodes","agent_url")
