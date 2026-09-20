from alembic import op
import sqlalchemy as sa
revision="102_mfa"
down_revision="101_bootstrap"
branch_labels=None
depends_on=None
def upgrade():op.add_column("admins",sa.Column("mfa_secret_encrypted",sa.Text(),nullable=True))
def downgrade():op.drop_column("admins","mfa_secret_encrypted")
