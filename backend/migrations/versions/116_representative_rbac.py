from alembic import op
import sqlalchemy as sa

revision="116_representative_rbac"
down_revision="115_traffic_snapshots"
branch_labels=None
depends_on=None

def upgrade():
    op.execute("ALTER TYPE rolename ADD VALUE IF NOT EXISTS 'representative'")
    op.add_column("clients",sa.Column("created_by_admin_id",sa.String(length=36),sa.ForeignKey("admins.id",ondelete="SET NULL"),nullable=True))
    op.create_index("ix_clients_created_by_admin_id","clients",["created_by_admin_id"])
    op.create_table(
        "admin_inbound_scopes",
        sa.Column("admin_id",sa.String(length=36),sa.ForeignKey("admins.id",ondelete="CASCADE"),primary_key=True),
        sa.Column("inbound_id",sa.String(length=36),sa.ForeignKey("inbounds.id",ondelete="CASCADE"),primary_key=True),
    )
    op.execute("ALTER TABLE admin_inbound_scopes ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE admin_inbound_scopes FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY admin_inbound_scopes_tenant_isolation ON admin_inbound_scopes
        USING (
          current_setting('app.is_platform',true)='true'
          OR EXISTS (
            SELECT 1 FROM admins a
            WHERE a.id=admin_inbound_scopes.admin_id
              AND a.tenant_id::text=current_setting('app.tenant_id',true)
          )
        )
        WITH CHECK (
          current_setting('app.is_platform',true)='true'
          OR EXISTS (
            SELECT 1 FROM admins a
            WHERE a.id=admin_inbound_scopes.admin_id
              AND a.tenant_id::text=current_setting('app.tenant_id',true)
          )
        )""")

def downgrade():
    op.execute("DROP POLICY IF EXISTS admin_inbound_scopes_tenant_isolation ON admin_inbound_scopes")
    op.execute("ALTER TABLE admin_inbound_scopes NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE admin_inbound_scopes DISABLE ROW LEVEL SECURITY")
    op.drop_table("admin_inbound_scopes")
    op.drop_index("ix_clients_created_by_admin_id",table_name="clients")
    op.drop_column("clients","created_by_admin_id")
    # PostgreSQL enum values are intentionally not removed on downgrade.
