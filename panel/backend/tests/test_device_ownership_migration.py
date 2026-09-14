"""Device ownership migration (0019) tests.

The legacy chain ``0001..0018`` is PostgreSQL-only (it uses ``ALTER COLUMN ... TYPE``), so these
tests stage the subset of the ``0018`` schema they need on an isolated SQLite file database, stamp
the revision marker ``0018``, and then run the *real* Alembic migration for ``0019`` against it.

The database URL is always constructed from ``tmp_path`` inside the test: the ambient
``DATABASE_URL`` is never used as migration input (it is only redirected to the isolated file), and
``_alembic`` refuses to run when the two disagree.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.util import CommandError

from app.database import Base

BACKEND_ROOT = Path(__file__).resolve().parents[1]

# The `0018` schema subset touched by the device ownership migration. ``created_at`` is NOT NULL on
# both tables in the real chain (0001 created it that way), so the staged subset mirrors that.
LEGACY_DDL = (
    """
    CREATE TABLE users (
        id VARCHAR NOT NULL PRIMARY KEY,
        name VARCHAR NOT NULL UNIQUE,
        is_blocked BOOLEAN NOT NULL DEFAULT 0,
        lifecycle_status VARCHAR NOT NULL DEFAULT 'active',
        created_at DATETIME NOT NULL,
        public_key VARCHAR,
        private_key VARCHAR,
        vpn_ip VARCHAR
    )
    """,
    """
    CREATE TABLE nodes (
        id VARCHAR NOT NULL PRIMARY KEY,
        name VARCHAR NOT NULL,
        url VARCHAR NOT NULL,
        token VARCHAR NOT NULL
    )
    """,
    """
    CREATE TABLE peers (
        id VARCHAR NOT NULL PRIMARY KEY,
        node_id VARCHAR NOT NULL REFERENCES nodes (id),
        user_id VARCHAR NOT NULL REFERENCES users (id),
        created_at DATETIME NOT NULL,
        status VARCHAR NOT NULL DEFAULT 'pending',
        psk_key VARCHAR,
        raw_rx BIGINT,
        raw_tx BIGINT,
        last_handshake DATETIME,
        endpoint VARCHAR,
        CONSTRAINT uq_peers_node_user UNIQUE (node_id, user_id)
    )
    """,
    """
    CREATE TABLE peer_traffic_samples (
        id VARCHAR NOT NULL PRIMARY KEY,
        peer_id VARCHAR NOT NULL REFERENCES peers (id) ON DELETE CASCADE,
        sampled_at DATETIME NOT NULL,
        rx_bytes BIGINT NOT NULL DEFAULT 0,
        tx_bytes BIGINT NOT NULL DEFAULT 0
    )
    """,
)

# id, name, is_blocked, created_at, public_key, private_key, vpn_ip
LEGACY_USERS = (
    ('user-full', 'alice', 0, '2026-01-01 10:00:00', 'alice-pub', 'alice-priv', '10.8.0.2'),
    ('user-blocked', 'bob', 1, '2026-01-02 10:00:00', 'bob-pub', 'bob-priv', '10.8.0.3'),
    ('user-empty', 'carol', 0, '2026-01-03 10:00:00', None, None, None),
)

# id, node_id, user_id, created_at, status, psk_key, raw_rx, raw_tx
LEGACY_PEERS = (
    ('peer-a1', 'node-1', 'user-full', '2026-01-04 10:00:00', 'active', 'psk-a1', 100, 200),
    ('peer-a2', 'node-2', 'user-full', '2026-01-05 10:00:00', 'pending', 'psk-a2', None, None),
    ('peer-b1', 'node-1', 'user-blocked', '2026-01-06 10:00:00', 'pending_delete', 'psk-b1', 5, 7),
)

OWNERSHIP_TABLES = ('devices', 'peers')


def _alembic(action: str, url: str, revision: str) -> None:
    # Guard against ever pointing a migration at anything but the isolated test database.
    assert os.environ['DATABASE_URL'] == url, (
        f'refusing to run alembic {action} against {os.environ["DATABASE_URL"]!r}'
    )
    config = Config(str(BACKEND_ROOT / 'alembic.ini'))
    config.set_main_option('script_location', str(BACKEND_ROOT / 'migrations'))
    if action == 'upgrade':
        command.upgrade(config, revision)
    elif action == 'downgrade':
        command.downgrade(config, revision)
    elif action == 'stamp':
        command.stamp(config, revision)
    else:  # pragma: no cover - defensive
        raise ValueError(action)


def _rows(db_path: str, query: str) -> list[tuple[Any, ...]]:
    with sqlite3.connect(db_path) as conn:
        return conn.execute(query).fetchall()


def _alembic_version(db_path: str) -> str:
    return str(_rows(db_path, 'SELECT version_num FROM alembic_version')[0][0])


def _schema_facts(engine: sa.Engine, tables: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Structural facts SQLAlchemy sees in a database: columns, keys, uniques, foreign keys."""
    inspector = sa.inspect(engine)
    return {
        table: {
            'columns': {
                column['name']: bool(column['nullable']) for column in inspector.get_columns(table)
            },
            'primary_key': sorted(inspector.get_pk_constraint(table)['constrained_columns'] or ()),
            'uniques': {
                tuple(sorted(constraint['column_names']))
                for constraint in inspector.get_unique_constraints(table)
            },
            'foreign_keys': {
                (
                    tuple(sorted(constraint['constrained_columns'])),
                    constraint['referred_table'],
                    tuple(sorted(constraint['referred_columns'] or ())),
                )
                for constraint in inspector.get_foreign_keys(table)
            },
            'indexes': {
                (index['name'], tuple(index['column_names'] or ()))
                for index in inspector.get_indexes(table)
            },
        }
        for table in tables
    }


def _seed_legacy_db(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    users: tuple[tuple[Any, ...], ...] = LEGACY_USERS,
    peers: tuple[tuple[Any, ...], ...] = LEGACY_PEERS,
) -> tuple[str, str]:
    """Isolated `0018` database with legacy users, peers and traffic history."""
    db_path = str(tmp_path / 'device-ownership.db')
    url = f'sqlite+aiosqlite:///{db_path}'
    # The migration runner reads DATABASE_URL from the environment; point it at our isolated file.
    monkeypatch.setenv('DATABASE_URL', url)
    with sqlite3.connect(db_path) as conn:
        for statement in LEGACY_DDL:
            conn.execute(statement)
        conn.executemany(
            'INSERT INTO nodes (id, name, url, token) VALUES (?, ?, ?, ?)',
            [
                ('node-1', 'node-1', 'http://agent-1:8000', 'token-1'),
                ('node-2', 'node-2', 'http://agent-2:8000', 'token-2'),
            ],
        )
        conn.executemany(
            """
            INSERT INTO users (id, name, is_blocked, created_at, public_key, private_key, vpn_ip)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            users,
        )
        conn.executemany(
            """
            INSERT INTO peers (id, node_id, user_id, created_at, status, psk_key, raw_rx, raw_tx)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            peers,
        )
        conn.execute(
            """
            INSERT INTO peer_traffic_samples (id, peer_id, sampled_at, rx_bytes, tx_bytes)
            VALUES (?, ?, ?, ?, ?)
            """,
            ('sample-1', 'peer-a1', '2026-01-07 10:00:00', 100, 200),
        )
        conn.commit()
    _alembic('stamp', url, '0018')
    return url, db_path


@pytest.fixture()
def legacy_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    return _seed_legacy_db(tmp_path, monkeypatch)


async def test_upgrade_backfills_exactly_one_default_device_per_user(legacy_db) -> None:
    url, db_path = legacy_db

    await asyncio.to_thread(_alembic, 'upgrade', url, '0019')

    assert _alembic_version(db_path) == '0019'

    devices = _rows(
        db_path,
        'SELECT id, user_id, name, public_key, private_key, vpn_ip, is_legacy_default, deleted_at'
        ' FROM devices ORDER BY user_id',
    )
    assert len(devices) == len(LEGACY_USERS) == 3
    by_user = {row[1]: row for row in devices}
    for user_id, _name, _blocked, _created, public_key, private_key, vpn_ip in LEGACY_USERS:
        device = by_user[user_id]
        assert device[0]  # generated device id
        assert device[2] == 'Default'
        assert (device[3], device[4], device[5]) == (public_key, private_key, vpn_ip)
        assert device[6] == 1
        assert device[7] is None

    peers = _rows(db_path, 'SELECT id, user_id, device_id, psk_key, status FROM peers ORDER BY id')
    assert [row[0] for row in peers] == ['peer-a1', 'peer-a2', 'peer-b1']
    for peer_id, user_id, device_id, _psk_key, status in peers:
        assert device_id == by_user[user_id][0], peer_id
        assert status in {'active', 'pending', 'pending_delete'}
    assert {row[0]: row[3] for row in peers} == {
        'peer-a1': 'psk-a1',
        'peer-a2': 'psk-a2',
        'peer-b1': 'psk-b1',
    }
    # both peers of the same owner, on different nodes, map to the same migration device
    peer_device = {row[0]: row[2] for row in peers}
    assert by_user['user-full'][0] == peer_device['peer-a1']
    assert by_user['user-full'][0] == peer_device['peer-a2']
    assert all(row[2] is not None for row in peers)

    # traffic history survives untouched
    assert _rows(db_path, 'SELECT id, peer_id, rx_bytes, tx_bytes FROM peer_traffic_samples') == [
        ('sample-1', 'peer-a1', 100, 200)
    ]

    # legacy user key material is retained for safe expansion
    legacy = {
        row[0]: row[1:]
        for row in _rows(
            db_path, 'SELECT id, public_key, private_key, vpn_ip, device_limit FROM users'
        )
    }
    assert legacy['user-full'][:3] == ('alice-pub', 'alice-priv', '10.8.0.2')
    assert legacy['user-blocked'][:3] == ('bob-pub', 'bob-priv', '10.8.0.3')
    assert legacy['user-empty'][:3] == (None, None, None)
    assert all(row[3] == 0 for row in legacy.values())

    # the per-user peer uniqueness constraint is replaced by the per-device one
    peers_sql = _rows(db_path, "SELECT sql FROM sqlite_master WHERE name = 'peers'")[0][0]
    assert 'uq_peers_node_user' not in peers_sql
    assert 'uq_peers_node_device' in peers_sql


async def test_migrated_schema_matches_orm_ownership_guarantees(legacy_db, tmp_path) -> None:
    """The migrated database must expose the structure the ORM declares.

    ``devices`` is created entirely by this migration, so it is compared in full - after the
    additive ``0020`` release-metadata migration, since that is the head the ORM describes.
    ``peers`` is staged here from a subset of the ``0018`` schema, so only the columns that subset
    defines are compared - but keys, unique constraints and foreign keys are compared exhaustively,
    which is what catches a migration that forgets ``fk_peers_device_owner`` or the ``NOT NULL`` on
    ``device_id``.
    """
    url, db_path = legacy_db
    await asyncio.to_thread(_alembic, 'upgrade', url, '0020')

    reference_engine = sa.create_engine(f'sqlite:///{tmp_path / "orm-reference.db"}')
    try:
        Base.metadata.create_all(reference_engine)
        reference = _schema_facts(reference_engine, OWNERSHIP_TABLES)
    finally:
        reference_engine.dispose()

    migrated_engine = sa.create_engine(f'sqlite:///{db_path}')
    try:
        migrated = _schema_facts(migrated_engine, OWNERSHIP_TABLES)
    finally:
        migrated_engine.dispose()

    assert migrated['devices'] == reference['devices']

    staged_columns = migrated['peers']['columns']
    orm_peer_columns = reference['peers']['columns']
    assert 'device_id' in staged_columns
    assert staged_columns['device_id'] is False  # NOT NULL: every peer belongs to a device
    for column in sorted(staged_columns):
        assert staged_columns[column] == orm_peer_columns[column], column
    assert migrated['peers']['uniques'] == reference['peers']['uniques']
    assert migrated['peers']['foreign_keys'] == reference['peers']['foreign_keys']
    # the ownership foreign key is the composite one, not a bare device_id reference
    assert (
        ('device_id', 'user_id'),
        'devices',
        ('id', 'user_id'),
    ) in migrated['peers']['foreign_keys']


async def test_upgrade_refused_when_legacy_public_keys_are_duplicated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Duplicate client keys make node results ambiguous, so the upgrade must refuse up front."""
    url, db_path = _seed_legacy_db(
        tmp_path,
        monkeypatch,
        users=(
            *LEGACY_USERS,
            (
                'user-copy',
                'dave',
                0,
                '2026-01-04 10:00:00',
                'alice-pub',
                'dave-priv',
                '10.8.0.4',
            ),
        ),
    )

    with pytest.raises((CommandError, RuntimeError), match='unique'):
        await asyncio.to_thread(_alembic, 'upgrade', url, '0019')

    # refused before anything was created: no partial schema, no lost data
    assert _alembic_version(db_path) == '0018'
    tables = {row[0] for row in _rows(db_path, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert 'devices' not in tables
    assert _rows(db_path, 'SELECT COUNT(*) FROM peers')[0][0] == len(LEGACY_PEERS)


async def test_upgrade_refused_when_legacy_public_keys_are_empty_and_duplicated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Empty strings are values under the devices unique constraint, not missing keys."""
    url, db_path = _seed_legacy_db(
        tmp_path,
        monkeypatch,
        users=(
            *LEGACY_USERS,
            (
                'user-empty-key-one',
                'dave',
                0,
                '2026-01-04 10:00:00',
                '',
                'dave-priv',
                '10.8.0.4',
            ),
            (
                'user-empty-key-two',
                'erin',
                0,
                '2026-01-05 10:00:00',
                '',
                'erin-priv',
                '10.8.0.5',
            ),
        ),
    )

    with pytest.raises((CommandError, RuntimeError), match='unique'):
        await asyncio.to_thread(_alembic, 'upgrade', url, '0019')

    assert _alembic_version(db_path) == '0018'
    tables = {row[0] for row in _rows(db_path, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert 'devices' not in tables
    assert _rows(db_path, 'SELECT COUNT(*) FROM users')[0][0] == len(LEGACY_USERS) + 2


async def test_upgrade_refused_when_legacy_vpn_ips_are_duplicated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``devices.vpn_ip`` is unique, so two users sharing a legacy IP must be refused up front."""
    url, db_path = _seed_legacy_db(
        tmp_path,
        monkeypatch,
        users=(
            *LEGACY_USERS,
            (
                'user-ip-copy',
                'dave',
                0,
                '2026-01-05 10:00:00',
                'dave-pub',
                'dave-priv',
                '10.8.0.2',  # same VPN IP as user-full
            ),
        ),
    )

    with pytest.raises((CommandError, RuntimeError), match='VPN IP'):
        await asyncio.to_thread(_alembic, 'upgrade', url, '0019')

    # refused before any schema change or backfill: the legacy database is untouched
    assert _alembic_version(db_path) == '0018'
    tables = {row[0] for row in _rows(db_path, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert 'devices' not in tables
    assert _rows(db_path, 'SELECT COUNT(*) FROM users')[0][0] == len(LEGACY_USERS) + 1


async def test_upgrade_refused_when_peers_reference_a_missing_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A peer whose owner is gone cannot be adopted by a Default device; refuse instead."""
    url, db_path = _seed_legacy_db(
        tmp_path,
        monkeypatch,
        peers=(
            *LEGACY_PEERS,
            (
                'peer-orphan',
                'node-1',
                'user-missing',
                '2026-01-08 10:00:00',
                'pending',
                'psk-orphan',
                None,
                None,
            ),
        ),
    )

    with pytest.raises((CommandError, RuntimeError), match='orphaned'):
        await asyncio.to_thread(_alembic, 'upgrade', url, '0019')

    assert _alembic_version(db_path) == '0018'
    tables = {row[0] for row in _rows(db_path, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert 'devices' not in tables
    assert _rows(db_path, 'SELECT COUNT(*) FROM peers')[0][0] == len(LEGACY_PEERS) + 1


async def test_downgrade_refused_when_new_device_credentials_exist(legacy_db) -> None:
    url, db_path = legacy_db
    await asyncio.to_thread(_alembic, 'upgrade', url, '0019')

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO devices
                (id, user_id, name, public_key, private_key, vpn_ip, is_legacy_default, deleted_at,
                 created_at)
            VALUES (?, 'user-full', 'phone', 'phone-pub', 'phone-priv', '10.8.0.9', 0, NULL,
                    '2026-09-01 10:00:00')
            """,
            ('second-device',),
        )
        conn.commit()

    with pytest.raises((CommandError, RuntimeError), match='downgrade'):
        await asyncio.to_thread(_alembic, 'downgrade', url, '0018')

    # the refused downgrade must not have changed anything
    assert _alembic_version(db_path) == '0019'
    assert _rows(db_path, 'SELECT COUNT(*) FROM devices')[0][0] == 4


async def test_downgrade_refused_when_a_device_is_tombstoned(legacy_db) -> None:
    """Deletion intent is not representable in 0018, so a tombstone must block the downgrade.

    0018 has no device deletion at all: copying a deleted Default device's credentials back onto
    the user row would resurrect the configuration the operator deleted and restore the deleted
    peer as a live per-user peer.
    """
    url, db_path = legacy_db
    await asyncio.to_thread(_alembic, 'upgrade', url, '0019')

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE devices SET deleted_at = '2026-09-02 10:00:00' WHERE user_id = 'user-full'"
        )
        conn.execute("UPDATE peers SET status = 'pending_delete' WHERE user_id = 'user-full'")
        conn.commit()

    with pytest.raises((CommandError, RuntimeError), match='downgrade'):
        await asyncio.to_thread(_alembic, 'downgrade', url, '0018')

    assert _alembic_version(db_path) == '0019'
    assert _rows(db_path, "SELECT public_key FROM users WHERE id = 'user-full'") == [('alice-pub',)]
    assert _rows(db_path, 'SELECT COUNT(*) FROM devices WHERE deleted_at IS NOT NULL')[0][0] == 1
    peers_sql = _rows(db_path, "SELECT sql FROM sqlite_master WHERE name = 'peers'")[0][0]
    assert 'device_id' in peers_sql


async def test_downgrade_restores_legacy_schema_when_only_migration_device_exists(
    legacy_db,
) -> None:
    url, db_path = legacy_db
    await asyncio.to_thread(_alembic, 'upgrade', url, '0019')

    await asyncio.to_thread(_alembic, 'downgrade', url, '0018')

    assert _alembic_version(db_path) == '0018'
    tables = {row[0] for row in _rows(db_path, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert 'devices' not in tables
    peers_sql = _rows(db_path, "SELECT sql FROM sqlite_master WHERE name = 'peers'")[0][0]
    assert 'device_id' not in peers_sql
    assert 'fk_peers_device_owner' not in peers_sql
    assert 'uq_peers_node_user' in peers_sql
    user_columns = {row[1] for row in _rows(db_path, 'PRAGMA table_info(users)')}
    assert 'device_limit' not in user_columns
    legacy = {row[0]: row[1:] for row in _rows(db_path, 'SELECT id, public_key, vpn_ip FROM users')}
    assert legacy['user-full'] == ('alice-pub', '10.8.0.2')
    assert legacy['user-empty'] == (None, None)


async def test_migration_0020_adds_release_metadata_without_touching_any_data(legacy_db) -> None:
    """``0020`` is additive: it only gives a released address somewhere to be recorded.

    Releasing is a runtime decision (a node must first confirm the peer is gone), so the migration
    must not release anything, recompute a key, move an IP or touch a peer row. It only adds the two
    nullable ``devices`` columns the release path writes.
    """
    url, db_path = legacy_db
    await asyncio.to_thread(_alembic, 'upgrade', url, '0019')

    devices_sql = (
        'SELECT id, user_id, name, public_key, private_key, vpn_ip FROM devices ORDER BY id'
    )
    peers_sql = 'SELECT id, device_id, psk_key, status, raw_rx, raw_tx FROM peers ORDER BY id'
    users_sql = 'SELECT id, public_key, private_key, vpn_ip FROM users ORDER BY id'
    devices_before = _rows(db_path, devices_sql)
    peers_before = _rows(db_path, peers_sql)
    users_before = _rows(db_path, users_sql)

    await asyncio.to_thread(_alembic, 'upgrade', url, '0020')

    assert _alembic_version(db_path) == '0020'
    columns = {row[1]: row for row in _rows(db_path, 'PRAGMA table_info(devices)')}
    assert 'released_vpn_ip' in columns
    assert 'ip_released_at' in columns
    assert columns['released_vpn_ip'][3] == 0  # nullable: only a release ever fills it
    assert columns['ip_released_at'][3] == 0
    # no release, no key change, no IP or peer-row movement
    assert _rows(db_path, devices_sql) == devices_before
    assert _rows(db_path, peers_sql) == peers_before
    assert _rows(db_path, users_sql) == users_before
    assert _rows(db_path, 'SELECT released_vpn_ip, ip_released_at FROM devices') == [
        (None, None)
    ] * len(devices_before)
    # every migrated account still owns the address its Default device inherited
    inherited = {row[1]: row[5] for row in devices_before}
    assert inherited['user-full'] == '10.8.0.2'
    assert inherited['user-blocked'] == '10.8.0.3'


async def test_downgrade_from_0020_keeps_a_tombstone_refused(legacy_db) -> None:
    """0020's columns go away; the 0019 refusal is what protects a deleted device."""
    url, db_path = legacy_db
    await asyncio.to_thread(_alembic, 'upgrade', url, '0020')

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE devices SET deleted_at = '2026-09-02 10:00:00' WHERE user_id = 'user-full'"
        )
        conn.commit()

    with pytest.raises((CommandError, RuntimeError), match='downgrade'):
        await asyncio.to_thread(_alembic, 'downgrade', url, '0018')

    assert _alembic_version(db_path) == '0019'
    assert _rows(db_path, 'SELECT COUNT(*) FROM devices')[0][0] == len(LEGACY_USERS)
