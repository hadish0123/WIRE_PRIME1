"""device ownership: devices table, peer.device_id, user device limit

Revision ID: 0019
Revises: 0018
Create Date: 2026-09-11

Every user that exists when this migration runs receives exactly one device named ``Default`` that
inherits the user's key material, VPN IP, peer rows (ids and PSKs) and traffic history. Nothing is
regenerated and no peer row is deleted, including blocked users and accounts with no keys.

Database-level guarantees added here, matching ``app.models`` exactly:

- ``peers.device_id`` is ``NOT NULL`` and part of the composite ownership foreign key
  ``fk_peers_device_owner`` ``(device_id, user_id) -> devices (id, user_id)``, so a peer can never
  point at a device of a different user or at a device that does not exist.
- ``devices.vpn_ip`` and ``devices.public_key`` are unique among devices. Node results are matched
  by public key, so two devices sharing a key would be indistinguishable; the legacy per-user
  columns were never unique, so ``upgrade`` refuses to run when it finds duplicate keys or duplicate
  VPN IPs among existing users instead of failing halfway through the backfill.
- ``uq_peers_node_user`` is replaced by ``uq_peers_node_device``: one node may hold several peers of
  the same owner (one per device).

Deployment note: this migration introduces the ownership model that the running application writes
to. Old backend writers must not be started against the migrated schema (they do not set
``peers.device_id``) and the new backend must not be started before this migration has been applied;
there is no lazy backfill at runtime. Apply the migration with the backend stopped, then start the
new backend. Downgrade is refused while any device is tombstoned or any non-migration device exists:
the legacy per-user schema cannot express device deletion and would resurrect deleted credentials.
"""

import uuid

import sqlalchemy as sa
from alembic import op

revision = '0019'
down_revision = '0018'
branch_labels = None
depends_on = None

DEFAULT_DEVICE_NAME = 'Default'


def _refuse_unmappable_legacy_data() -> None:
    """Fail with an actionable message instead of a constraint error halfway through the upgrade."""
    bind = op.get_bind()
    duplicate_keys = bind.execute(
        sa.text(
            """
            SELECT public_key, COUNT(*) AS owners
            FROM users
            WHERE public_key IS NOT NULL
            GROUP BY public_key
            HAVING COUNT(*) > 1
            """
        )
    ).fetchall()
    if duplicate_keys:
        key, owners = duplicate_keys[0]
        raise RuntimeError(
            'refusing to migrate to 0019: '
            f'{len(duplicate_keys)} client public key(s) are shared by several users '
            f'(for example {key!r} by {owners} users). Node results are matched by public key, so '
            'every device key must be unique; resolve the duplicates before upgrading.'
        )

    # ``devices.vpn_ip`` is unique among devices (the legacy per-user column never was), so two
    # users sharing an IP would fail the backfill halfway through with a constraint error instead
    # of an actionable message. NULLs are allowed to repeat; empty strings are not, exactly like the
    # database-level unique constraint the backfill inserts into.
    duplicate_ips = bind.execute(
        sa.text(
            """
            SELECT vpn_ip, COUNT(*) AS owners
            FROM users
            WHERE vpn_ip IS NOT NULL
            GROUP BY vpn_ip
            HAVING COUNT(*) > 1
            """
        )
    ).fetchall()
    if duplicate_ips:
        ip, owners = duplicate_ips[0]
        raise RuntimeError(
            'refusing to migrate to 0019: '
            f'{len(duplicate_ips)} legacy VPN IP address(es) are shared by several users '
            f'(for example {ip!r} by {owners} users). Every device owns exactly one VPN IP and the '
            'devices table enforces that, so give each user a distinct IP before upgrading.'
        )

    orphaned_peers = bind.execute(
        sa.text(
            """
            SELECT COUNT(*)
            FROM peers
            LEFT JOIN users ON users.id = peers.user_id
            WHERE users.id IS NULL
            """
        )
    ).scalar()
    if orphaned_peers:
        raise RuntimeError(
            'refusing to migrate to 0019: '
            f'{orphaned_peers} peer(s) reference a missing user, so no Default device can own '
            'them; remove the orphaned peer rows before upgrading.'
        )


def _backfill_default_devices() -> None:
    bind = op.get_bind()
    users = bind.execute(
        sa.text('SELECT id, created_at, public_key, private_key, vpn_ip FROM users')
    ).fetchall()
    for user_id, created_at, public_key, private_key, vpn_ip in users:
        device_id = str(uuid.uuid4())
        bind.execute(
            sa.text(
                """
                INSERT INTO devices
                    (id, user_id, name, public_key, private_key, vpn_ip, is_legacy_default,
                     deleted_at, created_at)
                VALUES
                    (:id, :user_id, :name, :public_key, :private_key, :vpn_ip, :is_legacy_default,
                     NULL, :created_at)
                """
            ),
            {
                'id': device_id,
                'user_id': user_id,
                'name': DEFAULT_DEVICE_NAME,
                'public_key': public_key,
                'private_key': private_key,
                'vpn_ip': vpn_ip,
                'is_legacy_default': True,
                'created_at': created_at,
            },
        )
        bind.execute(
            sa.text('UPDATE peers SET device_id = :device_id WHERE user_id = :user_id'),
            {'device_id': device_id, 'user_id': user_id},
        )


def _refuse_lossy_downgrade() -> None:
    bind = op.get_bind()
    tombstoned_devices = bind.execute(
        sa.text('SELECT COUNT(*) FROM devices WHERE deleted_at IS NOT NULL')
    ).scalar()
    if tombstoned_devices:
        raise RuntimeError(
            'refusing lossy downgrade to 0018: '
            f'{tombstoned_devices} deleted device(s) would come back as live per-user credentials, '
            'because the legacy schema has no way to express device deletion'
        )

    non_legacy_devices = bind.execute(
        sa.text('SELECT COUNT(*) FROM devices WHERE NOT is_legacy_default')
    ).scalar()
    non_legacy_peers = bind.execute(
        sa.text(
            """
            SELECT COUNT(*)
            FROM peers
            JOIN devices ON devices.id = peers.device_id
            WHERE NOT devices.is_legacy_default
            """
        )
    ).scalar()
    if (non_legacy_devices or 0) or (non_legacy_peers or 0):
        raise RuntimeError(
            'refusing lossy downgrade to 0018: '
            f'{non_legacy_devices} non-migration device(s) and {non_legacy_peers} peer(s) bound to '
            'them would lose their credentials and ownership on the legacy per-user schema'
        )


def _restore_legacy_user_credentials() -> None:
    """Copy live migration-device credentials back onto the user row.

    The legacy columns are normally untouched, but a device row is authoritative after the upgrade.
    Only live ``is_legacy_default`` devices are considered: tombstoned ones are refused earlier and
    must never be copied back.
    """
    op.get_bind().execute(
        sa.text(
            """
            UPDATE users
            SET public_key = COALESCE(
                    (
                        SELECT devices.public_key
                        FROM devices
                        WHERE devices.user_id = users.id
                          AND devices.is_legacy_default
                          AND devices.deleted_at IS NULL
                    ),
                    public_key
                ),
                private_key = COALESCE(
                    (
                        SELECT devices.private_key
                        FROM devices
                        WHERE devices.user_id = users.id
                          AND devices.is_legacy_default
                          AND devices.deleted_at IS NULL
                    ),
                    private_key
                ),
                vpn_ip = COALESCE(
                    (
                        SELECT devices.vpn_ip
                        FROM devices
                        WHERE devices.user_id = users.id
                          AND devices.is_legacy_default
                          AND devices.deleted_at IS NULL
                    ),
                    vpn_ip
                )
            WHERE EXISTS (
                SELECT 1
                FROM devices
                WHERE devices.user_id = users.id
                  AND devices.is_legacy_default
                  AND devices.deleted_at IS NULL
            )
            """
        )
    )


def upgrade() -> None:
    _refuse_unmappable_legacy_data()

    op.create_table(
        'devices',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('public_key', sa.String(), nullable=True),
        sa.Column('private_key', sa.String(), nullable=True),
        sa.Column('vpn_ip', sa.String(), nullable=True),
        sa.Column('is_legacy_default', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('id', 'user_id', name='uq_devices_id_user_id'),
        sa.UniqueConstraint('public_key', name='uq_devices_public_key'),
        sa.UniqueConstraint('vpn_ip', name='uq_devices_vpn_ip'),
    )
    op.create_index('ix_devices_user_id', 'devices', ['user_id'])

    op.add_column(
        'users',
        sa.Column('device_limit', sa.Integer(), nullable=False, server_default='0'),
    )
    op.add_column('peers', sa.Column('device_id', sa.String(), nullable=True))

    _backfill_default_devices()

    with op.batch_alter_table('peers') as batch:
        batch.drop_constraint('uq_peers_node_user', type_='unique')
        batch.alter_column('device_id', existing_type=sa.String(), nullable=False)
        batch.create_unique_constraint('uq_peers_node_device', ['node_id', 'device_id'])
        batch.create_foreign_key(
            'fk_peers_device_owner',
            'devices',
            ['device_id', 'user_id'],
            ['id', 'user_id'],
        )


def downgrade() -> None:
    _refuse_lossy_downgrade()
    _restore_legacy_user_credentials()

    with op.batch_alter_table('peers') as batch:
        batch.drop_constraint('fk_peers_device_owner', type_='foreignkey')
        batch.drop_constraint('uq_peers_node_device', type_='unique')
        batch.drop_column('device_id')
        batch.create_unique_constraint('uq_peers_node_user', ['node_id', 'user_id'])

    op.drop_index('ix_devices_user_id', table_name='devices')
    op.drop_table('devices')
    op.drop_column('users', 'device_limit')
