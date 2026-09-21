from alembic import op
import sqlalchemy as sa

revision = "118_device_last_seen_at"
down_revision = ("117_admin_quotas", "117_tenant_settings")
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("devices")}
    if "last_seen_at" not in columns:
        op.add_column(
            "devices",
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("devices")}
    if "last_seen_at" in columns:
        op.drop_column("devices", "last_seen_at")
