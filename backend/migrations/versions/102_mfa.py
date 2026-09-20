from alembic import op
import sqlalchemy as sa
revision="102_mfa";down_revision="101_bootstrap";branch_labels=None;depends_on=None
def upgrade():
 if "mfa_secret_encrypted" not in {x["name"] for x in sa.inspect(op.get_bind()).get_columns("admins")}:op.add_column("admins",sa.Column("mfa_secret_encrypted",sa.Text(),nullable=True))
def downgrade():
 if "mfa_secret_encrypted" in {x["name"] for x in sa.inspect(op.get_bind()).get_columns("admins")}:op.drop_column("admins","mfa_secret_encrypted")
