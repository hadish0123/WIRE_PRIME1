from alembic import op
revision="106_rls_credentials_counters"
down_revision="105_client_uniqueness"
branch_labels=None
depends_on=None
TABLES=["client_credentials","node_peer_counters"]
def upgrade():
 for t in TABLES:
  op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
  op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
  op.execute(f"""CREATE POLICY {t}_tenant_isolation ON {t}
    USING (current_setting('app.is_platform',true)='true' OR tenant_id::text=current_setting('app.tenant_id',true))
    WITH CHECK (current_setting('app.is_platform',true)='true' OR tenant_id::text=current_setting('app.tenant_id',true))""")
def downgrade():
 for t in reversed(TABLES):
  op.execute(f"DROP POLICY IF EXISTS {t}_tenant_isolation ON {t}")
  op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
  op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
