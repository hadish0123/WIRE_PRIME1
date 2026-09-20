from alembic import op
import sqlalchemy as sa
revision="105_client_uniqueness"
down_revision="104_device_addressing"
branch_labels=None
depends_on=None
def upgrade():
 op.create_unique_constraint("uq_clients_tenant_inbound_name","clients",["tenant_id","inbound_id","name"])
 op.create_unique_constraint("uq_clients_tenant_inbound_address","clients",["tenant_id","inbound_id","assigned_address"])
def downgrade():
 op.drop_constraint("uq_clients_tenant_inbound_address","clients",type_="unique")
 op.drop_constraint("uq_clients_tenant_inbound_name","clients",type_="unique")
