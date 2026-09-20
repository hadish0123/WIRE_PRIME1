from alembic import op
import sqlalchemy as sa

revision="117_admin_quotas"
down_revision="116_representative_rbac"
branch_labels=None
depends_on=None

def upgrade():
    op.add_column("admins", sa.Column("traffic_limit_bytes", sa.BigInteger(), nullable=False, server_default="0"))
    op.add_column("admins", sa.Column("quota_duration_days", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("admins", sa.Column("quota_started_at", sa.DateTime(timezone=True), nullable=True))
    op.alter_column("admins", "traffic_limit_bytes", server_default=None)
    op.alter_column("admins", "quota_duration_days", server_default=None)

def downgrade():
    op.drop_column("admins", "quota_started_at")
    op.drop_column("admins", "quota_duration_days")
    op.drop_column("admins", "traffic_limit_bytes")
