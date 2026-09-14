"""device ip release: released_vpn_ip and ip_released_at

Revision ID: 0020
Revises: 0019
Create Date: 2026-09-11

The VPN subnet is finite (``10.8.0.0/24`` holds roughly 250 client addresses), so an address has to
be recycled once the device that held it is gone. ``0019`` made ``devices.vpn_ip`` the only thing
that reserves an address - it copied each legacy address onto that account's Default device.
The runtime allocator no longer reads the frozen ``users.vpn_ip`` column. This migration adds
two nullable columns in which the release path records a hand-back:

- ``released_vpn_ip``: the address the device owned before it was handed back. Historical reference
  only, never a reservation - ``devices.vpn_ip`` is what reserves, and it is set to NULL on release.
- ``ip_released_at``: when that happened.

Purely additive, deliberately without a backfill. Releasing is a runtime decision: it happens only
once a node has confirmed every peer of the tombstoned device is gone, and it never regenerates a
key, never deletes a peer row and never touches the account's traffic history. Existing rows
therefore keep exactly the credential, IP and peer state ``0019`` left them; a device deleted before
this revision holds its address until its removal is confirmed again (removing its node, or deleting
it once more, runs the release path). Refusing to guess at backfill time keeps this migration from
moving an address out from under a peer a node may still hold.

Downgrade drops the two columns. A device that has already released its address is by definition
tombstoned, which ``0019``'s own lossy-downgrade guard refuses unless the deployment is a migration-
only one, so no released address can be silently dropped.
"""

import sqlalchemy as sa
from alembic import op

revision = '0020'
down_revision = '0019'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('devices', sa.Column('released_vpn_ip', sa.String(), nullable=True))
    op.add_column('devices', sa.Column('ip_released_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    # batch mode so the drop also works on SQLite, which cannot DROP COLUMN on an older server.
    with op.batch_alter_table('devices') as batch:
        batch.drop_column('released_vpn_ip')
        batch.drop_column('ip_released_at')
