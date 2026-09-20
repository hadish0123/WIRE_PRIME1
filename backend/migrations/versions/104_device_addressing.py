from alembic import op
import sqlalchemy as sa
revision="104_device_addressing"
down_revision="103_protocol_security"
branch_labels=None
depends_on=None
def upgrade():
 insp=sa.inspect(op.get_bind())
 dcols={x["name"] for x in insp.get_columns("devices")}
 if "assigned_address" not in dcols:op.add_column("devices",sa.Column("assigned_address",sa.String(120),nullable=True))
 ccols={x["name"] for x in insp.get_columns("client_credentials")}
 if "device_id" not in ccols:
  op.add_column("client_credentials",sa.Column("device_id",sa.String(36),nullable=True))
  op.create_foreign_key("fk_client_credentials_device","client_credentials","devices",["device_id"],["id"],ondelete="SET NULL")
  op.create_index("ix_client_credentials_device_id","client_credentials",["device_id"])
def downgrade():
 op.drop_index("ix_client_credentials_device_id",table_name="client_credentials")
 op.drop_constraint("fk_client_credentials_device","client_credentials",type_="foreignkey")
 op.drop_column("client_credentials","device_id")
 op.drop_column("devices","assigned_address")
