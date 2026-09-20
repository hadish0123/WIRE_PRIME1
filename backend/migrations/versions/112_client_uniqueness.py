from alembic import op
import sqlalchemy as sa

revision="112_client_uniqueness"
down_revision="111_device_addressing"
branch_labels=None
depends_on=None

def _has_unique(table, columns):
    insp=sa.inspect(op.get_bind())
    wanted=tuple(columns)
    for item in insp.get_unique_constraints(table):
        if tuple(item.get("column_names") or ()) == wanted:
            return True
    return False

def upgrade():
    if not _has_unique("clients", ["tenant_id","inbound_id","name"]):
        op.create_unique_constraint("uq_clients_tenant_inbound_name","clients",["tenant_id","inbound_id","name"])
    if not _has_unique("clients", ["tenant_id","inbound_id","assigned_address"]):
        op.create_unique_constraint("uq_clients_tenant_inbound_address","clients",["tenant_id","inbound_id","assigned_address"])

def downgrade():
    insp=sa.inspect(op.get_bind())
    names={x.get("name") for x in insp.get_unique_constraints("clients")}
    if "uq_clients_tenant_inbound_address" in names:
        op.drop_constraint("uq_clients_tenant_inbound_address","clients",type_="unique")
    if "uq_clients_tenant_inbound_name" in names:
        op.drop_constraint("uq_clients_tenant_inbound_name","clients",type_="unique")
