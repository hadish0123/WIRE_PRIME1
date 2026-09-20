from alembic import op
import sqlalchemy as sa
revision="101_bootstrap"
down_revision="100_rls"
branch_labels=None
depends_on=None
def upgrade():
 op.add_column("provisioning_tasks",sa.Column("bootstrap_token_hash",sa.String(128),nullable=True))
 op.add_column("provisioning_tasks",sa.Column("bootstrap_expires_at",sa.DateTime(timezone=True),nullable=True))
def downgrade():
 op.drop_column("provisioning_tasks","bootstrap_expires_at")
 op.drop_column("provisioning_tasks","bootstrap_token_hash")
