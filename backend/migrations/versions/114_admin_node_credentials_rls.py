from alembic import op

revision="114_admin_node_credentials_rls"
down_revision="113_credentials_rls"
branch_labels=None
depends_on=None

def upgrade():
    op.execute("ALTER TABLE admins ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE admins FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY admins_tenant_isolation ON admins
        USING (current_setting('app.is_platform',true)='true'
            OR tenant_id::text=current_setting('app.tenant_id',true))
        WITH CHECK (current_setting('app.is_platform',true)='true'
            OR tenant_id::text=current_setting('app.tenant_id',true))""")

    op.execute("ALTER TABLE node_credentials ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE node_credentials FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY node_credentials_tenant_isolation ON node_credentials
        USING (current_setting('app.is_platform',true)='true'
            OR EXISTS (
                SELECT 1 FROM nodes n
                WHERE n.id=node_credentials.node_id
                  AND n.tenant_id::text=current_setting('app.tenant_id',true)
            ))
        WITH CHECK (current_setting('app.is_platform',true)='true'
            OR EXISTS (
                SELECT 1 FROM nodes n
                WHERE n.id=node_credentials.node_id
                  AND n.tenant_id::text=current_setting('app.tenant_id',true)
            ))""")

    op.execute("ALTER TABLE admin_roles ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE admin_roles FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY admin_roles_tenant_isolation ON admin_roles
        USING (current_setting('app.is_platform',true)='true'
            OR EXISTS (
                SELECT 1 FROM admins a
                WHERE a.id=admin_roles.admin_id
                  AND a.tenant_id::text=current_setting('app.tenant_id',true)
            ))
        WITH CHECK (current_setting('app.is_platform',true)='true'
            OR EXISTS (
                SELECT 1 FROM admins a
                WHERE a.id=admin_roles.admin_id
                  AND a.tenant_id::text=current_setting('app.tenant_id',true)
            ))""")

def downgrade():
    op.execute("DROP POLICY IF EXISTS admin_roles_tenant_isolation ON admin_roles")
    op.execute("ALTER TABLE admin_roles NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE admin_roles DISABLE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS node_credentials_tenant_isolation ON node_credentials")
    op.execute("ALTER TABLE node_credentials NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE node_credentials DISABLE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS admins_tenant_isolation ON admins")
    op.execute("ALTER TABLE admins NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE admins DISABLE ROW LEVEL SECURITY")
