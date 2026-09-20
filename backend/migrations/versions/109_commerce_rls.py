from alembic import op
revision="109_commerce_rls";down_revision="108_commerce";branch_labels=None;depends_on=None
TABLES=["products","plans","orders","payments","subscriptions","wallets","wallet_transactions"]
def upgrade():
 for t in TABLES:
  tenant_expr="tenant_id::text=current_setting('app.tenant_id',true)" if t!="plans" and t!="payments" and t!="wallet_transactions" else ("product_id IN (SELECT id FROM products WHERE tenant_id::text=current_setting('app.tenant_id',true))" if t=="plans" else ("order_id IN (SELECT id FROM orders WHERE tenant_id::text=current_setting('app.tenant_id',true))" if t=="payments" else ("wallet_id IN (SELECT id FROM wallets WHERE tenant_id::text=current_setting('app.tenant_id',true))" if t=="wallet_transactions" else "true")))
  op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
  op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
  op.execute(f"""CREATE POLICY {t}_tenant_isolation ON {t}
 USING (current_setting('app.is_platform',true)='true' OR {tenant_expr})
 WITH CHECK (current_setting('app.is_platform',true)='true' OR {tenant_expr})""")
def downgrade():
 for t in reversed(TABLES):
  op.execute(f"DROP POLICY IF EXISTS {t}_tenant_isolation ON {t}")
  op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
  op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
