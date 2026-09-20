from alembic import op
revision="113_credentials_rls";down_revision="112_client_uniqueness";branch_labels=None;depends_on=None
def upgrade():
 op.execute("ALTER TABLE client_credentials ENABLE ROW LEVEL SECURITY")
 op.execute("ALTER TABLE client_credentials FORCE ROW LEVEL SECURITY")
 op.execute("""CREATE POLICY client_credentials_tenant_isolation ON client_credentials USING (current_setting('app.is_platform',true)='true' OR EXISTS (SELECT 1 FROM clients c WHERE c.id=client_credentials.client_id AND c.tenant_id::text=current_setting('app.tenant_id',true))) WITH CHECK (current_setting('app.is_platform',true)='true' OR EXISTS (SELECT 1 FROM clients c WHERE c.id=client_credentials.client_id AND c.tenant_id::text=current_setting('app.tenant_id',true)))""")
def downgrade():
 op.execute("DROP POLICY IF EXISTS client_credentials_tenant_isolation ON client_credentials");op.execute("ALTER TABLE client_credentials NO FORCE ROW LEVEL SECURITY");op.execute("ALTER TABLE client_credentials DISABLE ROW LEVEL SECURITY")
