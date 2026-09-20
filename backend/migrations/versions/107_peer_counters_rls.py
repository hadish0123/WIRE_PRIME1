from alembic import op
import sqlalchemy as sa
revision="107_peer_counters_rls";down_revision="106_peer_counters";branch_labels=None;depends_on=None
def upgrade():
 if "node_peer_counters" not in sa.inspect(op.get_bind()).get_table_names():return
 op.execute("ALTER TABLE node_peer_counters ENABLE ROW LEVEL SECURITY")
 op.execute("ALTER TABLE node_peer_counters FORCE ROW LEVEL SECURITY")
 op.execute("""DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname=current_schema() AND tablename='node_peer_counters' AND policyname='node_peer_counters_tenant_isolation') THEN
 CREATE POLICY node_peer_counters_tenant_isolation ON node_peer_counters
 USING (current_setting('app.is_platform',true)='true' OR tenant_id::text=current_setting('app.tenant_id',true))
 WITH CHECK (current_setting('app.is_platform',true)='true' OR tenant_id::text=current_setting('app.tenant_id',true));
 END IF; END $$""")
def downgrade():
 op.execute("DROP POLICY IF EXISTS node_peer_counters_tenant_isolation ON node_peer_counters")
 op.execute("ALTER TABLE node_peer_counters NO FORCE ROW LEVEL SECURITY")
 op.execute("ALTER TABLE node_peer_counters DISABLE ROW LEVEL SECURITY")
