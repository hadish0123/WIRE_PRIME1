from alembic import op
import sqlalchemy as sa
revision="111_device_addressing";down_revision="110_protocol_security";branch_labels=None;depends_on=None
def upgrade():
 insp=sa.inspect(op.get_bind())
 if "assigned_address" not in {x["name"] for x in insp.get_columns("devices")}:op.add_column("devices",sa.Column("assigned_address",sa.String(120),nullable=True))
 if "device_id" not in {x["name"] for x in insp.get_columns("client_credentials")}:
  op.add_column("client_credentials",sa.Column("device_id",sa.String(36),nullable=True))
  op.create_foreign_key("fk_client_credentials_device","client_credentials","devices",["device_id"],["id"],ondelete="SET NULL")
  op.create_index("ix_client_credentials_device_id","client_credentials",["device_id"])
def downgrade():
 op.drop_index("ix_client_credentials_device_id",table_name="client_credentials")
 op.drop_constraint("fk_client_credentials_device","client_credentials",type_="foreignkey")
 op.drop_column("client_credentials","device_id");op.drop_column("devices","assigned_address")
