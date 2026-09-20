from alembic import op
revision="100_rls"
down_revision="100_initial"
branch_labels=None
depends_on=None

TENANT_TABLES=[
    "nodes","inbounds","clients","devices","sessions","traffic_usage",
    "quotas","config_artifacts","provisioning_tasks","jobs","audit_logs","roles"
]

def upgrade():
    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"""CREATE POLICY {t}_tenant_isolation ON {t}
            USING (
                NULLIF(current_setting('app.is_platform',true),'')='true'
                OR tenant_id::text=NULLIF(current_setting('app.tenant_id',true),'')
            )
            WITH CHECK (
                NULLIF(current_setting('app.is_platform',true),'')='true'
                OR tenant_id::text=NULLIF(current_setting('app.tenant_id',true),'')
            )""")

def downgrade():
    for t in reversed(TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS {t}_tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
