from alembic import op
import sqlalchemy as sa
revision="117_tenant_settings"
down_revision="116_representative_rbac"
branch_labels=None
depends_on=None

def upgrade():
    op.create_table("tenant_settings",
        sa.Column("tenant_id",sa.String(36),sa.ForeignKey("tenants.id",ondelete="CASCADE"),primary_key=True),
        sa.Column("panel_name",sa.String(160),nullable=False,server_default="PRIMEVPN"),
        sa.Column("timezone",sa.String(80),nullable=False,server_default="UTC"),
        sa.Column("language",sa.String(10),nullable=False,server_default="fa"),
        sa.Column("default_protocol",sa.String(40),nullable=False,server_default="wireguard"),
        sa.Column("default_dns",sa.String(160),nullable=False,server_default="1.1.1.1"),
        sa.Column("default_client_quota_gb",sa.BigInteger(),nullable=False,server_default="0"),
        sa.Column("default_client_duration_days",sa.Integer(),nullable=False,server_default="0"),
        sa.Column("session_timeout_minutes",sa.Integer(),nullable=False,server_default="120"),
        sa.Column("audit_retention_days",sa.Integer(),nullable=False,server_default="365"),
        sa.Column("require_mfa",sa.Boolean(),nullable=False,server_default=sa.text("false")),
        sa.Column("updated_at",sa.DateTime(timezone=True),nullable=False,server_default=sa.func.now()),
    )
    op.execute("ALTER TABLE tenant_settings ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tenant_settings FORCE ROW LEVEL SECURITY")
    op.execute('''CREATE POLICY tenant_settings_isolation ON tenant_settings USING (current_setting('app.is_platform',true)='true' OR tenant_id::text=current_setting('app.tenant_id',true)) WITH CHECK (current_setting('app.is_platform',true)='true' OR tenant_id::text=current_setting('app.tenant_id',true))''')

def downgrade():
    op.execute("DROP POLICY IF EXISTS tenant_settings_isolation ON tenant_settings")
    op.execute("ALTER TABLE tenant_settings NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tenant_settings DISABLE ROW LEVEL SECURITY")
    op.drop_table("tenant_settings")
