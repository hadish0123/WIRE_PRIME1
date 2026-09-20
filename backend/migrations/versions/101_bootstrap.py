from alembic import op
import sqlalchemy as sa
revision="101_bootstrap";down_revision="100_rls";branch_labels=None;depends_on=None
def upgrade():
 insp=sa.inspect(op.get_bind());cols={x["name"] for x in insp.get_columns("provisioning_tasks")}
 if "bootstrap_token_hash" not in cols:op.add_column("provisioning_tasks",sa.Column("bootstrap_token_hash",sa.String(128),nullable=True))
 if "bootstrap_expires_at" not in cols:op.add_column("provisioning_tasks",sa.Column("bootstrap_expires_at",sa.DateTime(timezone=True),nullable=True))
def downgrade():
 insp=sa.inspect(op.get_bind());cols={x["name"] for x in insp.get_columns("provisioning_tasks")}
 if "bootstrap_expires_at" in cols:op.drop_column("provisioning_tasks","bootstrap_expires_at")
 if "bootstrap_token_hash" in cols:op.drop_column("provisioning_tasks","bootstrap_token_hash")
