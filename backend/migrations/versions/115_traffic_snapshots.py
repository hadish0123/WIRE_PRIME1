from alembic import op
import sqlalchemy as sa

revision="115_traffic_snapshots"
down_revision="114_admin_node_credentials_rls"
branch_labels=None
depends_on=None

def upgrade():
    op.create_table(
        "traffic_snapshots",
        sa.Column("id",sa.String(length=36),primary_key=True),
        sa.Column("tenant_id",sa.String(length=36),sa.ForeignKey("tenants.id",ondelete="CASCADE"),nullable=False,index=True),
        sa.Column("client_id",sa.String(length=36),sa.ForeignKey("clients.id",ondelete="CASCADE"),nullable=False,index=True),
        sa.Column("node_id",sa.String(length=36),sa.ForeignKey("nodes.id",ondelete="CASCADE"),nullable=False,index=True),
        sa.Column("inbound_id",sa.String(length=36),sa.ForeignKey("inbounds.id",ondelete="CASCADE"),nullable=False,index=True),
        sa.Column("bytes_in",sa.BigInteger(),nullable=False,server_default="0"),
        sa.Column("bytes_out",sa.BigInteger(),nullable=False,server_default="0"),
        sa.Column("captured_at",sa.DateTime(timezone=True),nullable=False,index=True),
    )
    op.execute("ALTER TABLE traffic_snapshots ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE traffic_snapshots FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY traffic_snapshots_tenant_isolation ON traffic_snapshots
        USING (current_setting('app.is_platform',true)='true'
            OR tenant_id::text=current_setting('app.tenant_id',true))
        WITH CHECK (current_setting('app.is_platform',true)='true'
            OR tenant_id::text=current_setting('app.tenant_id',true))""")
    op.create_index("ix_traffic_snapshots_tenant_captured","traffic_snapshots",["tenant_id","captured_at"])

def downgrade():
    op.drop_index("ix_traffic_snapshots_tenant_captured",table_name="traffic_snapshots")
    op.execute("DROP POLICY IF EXISTS traffic_snapshots_tenant_isolation ON traffic_snapshots")
    op.execute("ALTER TABLE traffic_snapshots NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE traffic_snapshots DISABLE ROW LEVEL SECURITY")
    op.drop_table("traffic_snapshots")
