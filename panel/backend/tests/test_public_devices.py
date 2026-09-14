"""Public device API: add/delete/list, device-aware downloads, readiness and authorization.

Every test drives the real HTTP surface (``/pub/u/...``, ``/internal/worker/...``) against the
database and asserts the persisted state, so the queue-intent and readiness contract is exercised
end to end instead of through service calls.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from http import HTTPStatus

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AsyncOperation, Device, Node, Peer, RemnawaveUser, User

NODE_METADATA = {'server_public_key': 'node-public', 'server_endpoint': 'vpn.example:51820'}

# Every config/QR/chunks form, device-scoped and legacy alike: no route may be a way around the
# account state or the per-node availability.
DOWNLOAD_PATHS = (
    'config/awg/node-1',
    'config/vpn/node-1',
    'qr/awg/node-1',
    'qr/vpn/node-1',
    'qr-chunks/vpn/node-1',
)


# ── fixtures ───────────────────────────────────────────────────────────────────


async def _seed_node(
    db: AsyncSession,
    node_id: str = 'node-1',
    name: str = 'node-1',
    **overrides,
) -> Node:
    data: dict = {
        'id': node_id,
        'name': name,
        'url': f'http://{node_id}-agent:8000',
        'token': 'node-token',
    }
    data.update(overrides)
    node = Node(**data)
    db.add(node)
    await db.commit()
    return node


async def _seed_user(db: AsyncSession, *, name: str = 'bob', **overrides) -> User:
    user = User(id=f'user-{name}', name=name, **overrides)
    db.add(user)
    await db.commit()
    return user


async def _seed_legacy_default(
    db: AsyncSession,
    user: User,
    *,
    name: str = 'Default',
    private_key: str = 'alice-private',
    vpn_ip: str = '10.8.0.2',
) -> Device:
    """The device migration 0019 creates: it inherits the retained per-user credentials."""
    device = Device(
        id=f'{user.id}-device-{name}',
        user_id=user.id,
        name=name,
        public_key=f'{private_key}-public',
        private_key=private_key,
        vpn_ip=vpn_ip,
        is_legacy_default=True,
    )
    db.add(device)
    await db.commit()
    return device


async def _seed_peer(
    db: AsyncSession,
    *,
    node: Node,
    device: Device,
    status: str = 'active',
    psk_key: str = 'peer-psk',
) -> Peer:
    peer = Peer(
        id=f'peer-{node.id}-{device.id}',
        node_id=node.id,
        user_id=device.user_id,
        device_id=device.id,
        status=status,
        psk_key=psk_key,
    )
    db.add(peer)
    await db.commit()
    return peer


async def _seed_remnawave_user(
    db: AsyncSession, *, name: str, status: str = 'ACTIVE', hwid_device_limit: int = 0, **overrides
) -> User:
    user = User(id=f'user-{name}', name=name)
    db.add(user)
    await db.flush()
    db.add(
        RemnawaveUser(
            user_id=user.id,
            remnawave_uuid=f'uuid-{name}',
            username=name,
            status=status,
            hwid_device_limit=hwid_device_limit,
            **overrides,
        )
    )
    await db.commit()
    return user


@pytest.fixture(autouse=True)
def _no_broker(monkeypatch) -> None:
    """Nothing here may reach RabbitMQ: publishes are recorded, not sent."""
    recorded: list[dict] = []

    async def _enqueue(node_id: str, **kwargs):
        recorded.append({'node_id': node_id, **kwargs})
        return {'command': 'sync_node', 'target_id': node_id, **kwargs}

    monkeypatch.setattr('app.routers.internal_worker.enqueue_sync_node', _enqueue)


@pytest.fixture()
def sync_enqueues(monkeypatch) -> list[dict]:
    """Record tracked sync_node publishes instead of talking to RabbitMQ."""
    calls: list[dict] = []

    async def _enqueue(node_id: str, **kwargs):
        calls.append({'node_id': node_id, **kwargs})
        return {'command': 'sync_node', 'target_id': node_id, **kwargs}

    monkeypatch.setattr('app.routers.internal_worker.enqueue_sync_node', _enqueue)
    return calls


async def _ack_peer(
    client: AsyncClient, worker_headers: dict[str, str], node_id: str, public_key: str
) -> None:
    resp = await client.post(
        f'/internal/worker/nodes/{node_id}/sync-result',
        json={
            'ok': True,
            'interface': {'public_key': 'node-public', 'listen_port': 51820},
            'peers': [{'public_key': public_key, 'status': 'active'}],
        },
        headers=worker_headers,
    )
    assert resp.status_code == HTTPStatus.OK


async def _fail_node_sync(
    client: AsyncClient,
    worker_headers: dict[str, str],
    node_id: str,
    *,
    error: str = 'agent unreachable',
) -> None:
    """A node result that reports a *failed* sync: diagnostics only, no peer state is applied."""
    resp = await client.post(
        f'/internal/worker/nodes/{node_id}/sync-result',
        json={'ok': False, 'error': error},
        headers=worker_headers,
    )
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()['status'] == 'failed'


# ── info: devices, legacy nodes and limits ─────────────────────────────────────


async def test_info_new_account_has_no_implicit_default(client: AsyncClient, db) -> None:
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='fresh')

    resp = await client.get(f'/pub/u/{user.public_token}/info')

    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    assert data['blocked'] is False
    assert data['devices'] == []
    assert data['nodes'] == []
    assert data['device_count'] == 0
    assert data['device_limit'] == 0
    assert data['can_add_device'] is True


async def test_info_remnawave_user_starts_empty(client: AsyncClient, db) -> None:
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_remnawave_user(db, name='rw-empty', hwid_device_limit=0)

    data = (await client.get(f'/pub/u/{user.public_token}/info')).json()

    assert data['devices'] == []
    assert data['nodes'] == []
    assert data['device_count'] == 0
    assert data['can_add_device'] is True


async def test_info_legacy_nodes_come_only_from_the_migration_default(
    client: AsyncClient, db
) -> None:
    node_one = await _seed_node(db, 'node-1', 'node-1', **NODE_METADATA)
    node_two = await _seed_node(
        db, 'node-2', 'node-2', server_public_key='node-2-public', server_endpoint='vpn2:51820'
    )
    user = await _seed_user(db, name='legacy', public_key='alice-public')
    default_device = await _seed_legacy_default(db, user)
    await _seed_peer(db, node=node_one, device=default_device, psk_key='default-psk')

    laptop = Device(
        id='laptop',
        user_id=user.id,
        name='laptop',
        public_key='laptop-public',
        private_key='laptop-private',
        vpn_ip='10.8.0.9',
    )
    db.add(laptop)
    await db.flush()
    await _seed_peer(db, node=node_two, device=laptop, psk_key='laptop-psk')

    data = (await client.get(f'/pub/u/{user.public_token}/info')).json()

    # Legacy nodes stay pinned to the migration device: the laptop's node is not listed.
    assert [node['id'] for node in data['nodes']] == ['node-1']
    assert data['nodes'][0]['ready'] is True
    assert data['nodes'][0]['vpn_uri'].startswith('vpn://')

    by_name = {device['name']: device for device in data['devices']}
    assert set(by_name) == {'Default', 'laptop'}
    assert by_name['Default']['status'] == 'ready'
    assert [node['id'] for node in by_name['Default']['nodes']] == ['node-1', 'node-2']
    # Each device shows its own per-node state; the unprovisioned node stays pending.
    assert [node['status'] for node in by_name['Default']['nodes']] == ['ready', 'pending']
    assert by_name['laptop']['status'] == 'ready'
    assert [node['status'] for node in by_name['laptop']['nodes']] == ['pending', 'ready']


async def test_info_device_limit_is_unlimited_when_zero(client: AsyncClient, db) -> None:
    user = await _seed_user(db, name='unlimited', device_limit=0)
    device = Device(
        id='d1', user_id=user.id, name='one', public_key='p', private_key='k', vpn_ip='10.8.0.3'
    )
    db.add(device)
    await db.commit()

    data = (await client.get(f'/pub/u/{user.public_token}/info')).json()

    assert data['device_limit'] == 0
    assert data['device_count'] == 1
    assert data['can_add_device'] is True


async def test_info_reports_limit_and_blocks_add_when_reached(client: AsyncClient, db) -> None:
    user = await _seed_user(db, name='capped', device_limit=1)
    db.add(
        Device(
            id='d1', user_id=user.id, name='one', public_key='p', private_key='k', vpn_ip='10.8.0.4'
        )
    )
    await db.commit()

    data = (await client.get(f'/pub/u/{user.public_token}/info')).json()

    assert data['device_limit'] == 1
    assert data['device_count'] == 1
    assert data['can_add_device'] is False


# ── add ────────────────────────────────────────────────────────────────────────


async def test_add_device_creates_pending_device_and_persists_sync_intent(
    client: AsyncClient, db, sync_enqueues: list[dict]
) -> None:
    await _seed_node(db, 'node-1', 'node-1', **NODE_METADATA)
    await _seed_node(
        db, 'node-2', 'node-2', server_public_key='node-2-public', server_endpoint='vpn2:51820'
    )
    user = await _seed_user(db, name='adder')

    resp = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'ноутбук 📱'})

    assert resp.status_code == HTTPStatus.CREATED
    body = resp.json()
    assert body['id']
    assert body['name'] == 'ноутбук 📱'
    assert body['status'] == 'pending'
    assert body['created_at']
    assert [node['id'] for node in body['nodes']] == ['node-1', 'node-2']
    assert all(node['status'] == 'pending' for node in body['nodes'])
    assert all(node['ready'] is False for node in body['nodes'])
    assert all(node['vpn_uri'] is None for node in body['nodes'])
    serialized = json.dumps(body)
    assert 'private_key' not in serialized
    assert 'psk' not in serialized

    peers = (await db.execute(select(Peer).where(Peer.device_id == body['id']))).scalars().all()
    assert {peer.node_id for peer in peers} == {'node-1', 'node-2'}
    assert all(peer.status == 'pending' for peer in peers)
    assert all(peer.psk_key for peer in peers)

    operations = (
        (await db.execute(select(AsyncOperation).where(AsyncOperation.kind == 'sync_node')))
        .scalars()
        .all()
    )
    assert {operation.target_id for operation in operations} == {'node-1', 'node-2'}
    assert all(operation.status == 'queued' for operation in operations)
    assert sorted(call['node_id'] for call in sync_enqueues) == ['node-1', 'node-2']
    assert {call['operation_id'] for call in sync_enqueues} == {
        operation.id for operation in operations
    }


async def test_add_device_keeps_durable_pending_state_when_publish_fails(
    client: AsyncClient, db, monkeypatch
) -> None:
    async def _enqueue(*args: object, **kwargs: object) -> None:
        raise RuntimeError(f'broker down: {args!r} {kwargs!r}')

    monkeypatch.setattr('app.routers.internal_worker.enqueue_sync_node', _enqueue)
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='broker-down')

    resp = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'laptop'})

    assert resp.status_code == HTTPStatus.CREATED
    body = resp.json()
    assert body['status'] == 'pending'
    assert all(node['ready'] is False for node in body['nodes'])

    device = await db.get(Device, body['id'])
    assert device is not None
    assert device.deleted_at is None
    peers = (await db.execute(select(Peer).where(Peer.device_id == body['id']))).scalars().all()
    assert [peer.status for peer in peers] == ['pending']

    operations = (
        (await db.execute(select(AsyncOperation).where(AsyncOperation.kind == 'sync_node')))
        .scalars()
        .all()
    )
    assert [operation.status for operation in operations] == ['enqueue_failed']

    # Never report a device as ready (or serve a config) on the strength of a failed publish.
    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    assert info['devices'][0]['status'] == 'pending'
    config = await client.get(f'/pub/u/{user.public_token}/devices/{body["id"]}/config/awg/node-1')
    assert config.status_code == HTTPStatus.SERVICE_UNAVAILABLE


@pytest.mark.parametrize(
    'name',
    ['', '   ', 'x' * 65, 'bad\nname', 'bad\tname', '\u202ehidden'],
)
async def test_add_device_rejects_invalid_names(client: AsyncClient, db, name: str) -> None:
    user = await _seed_user(db, name=f'invalid-{abs(hash(name))}')

    resp = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': name})

    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
    devices = (await db.execute(select(Device).where(Device.user_id == user.id))).scalars().all()
    assert devices == []


async def test_add_device_requires_a_name(client: AsyncClient, db) -> None:
    user = await _seed_user(db, name='nameless')

    resp = await client.post(f'/pub/u/{user.public_token}/devices', json={})

    assert resp.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


async def test_add_device_for_unknown_token_is_not_found(client: AsyncClient) -> None:
    resp = await client.post('/pub/u/no-such-token/devices', json={'name': 'laptop'})

    assert resp.status_code == HTTPStatus.NOT_FOUND


@pytest.mark.parametrize(
    ('limit', 'expected'),
    [(1, HTTPStatus.CONFLICT), (2, HTTPStatus.CREATED)],
)
async def test_add_device_enforces_local_limit(
    client: AsyncClient, db, limit: int, expected: int
) -> None:
    user = await _seed_user(db, name=f'local-limit-{limit}', device_limit=limit)
    db.add(
        Device(
            id='d1',
            user_id=user.id,
            name='one',
            public_key='p1',
            private_key='k1',
            vpn_ip='10.8.0.5',
        )
    )
    await db.commit()

    resp = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'two'})

    assert resp.status_code == expected
    if expected == HTTPStatus.CONFLICT:
        assert 'broker' not in json.dumps(resp.json())


async def test_add_device_uses_imported_remnawave_limit_and_zero_is_unlimited(
    client: AsyncClient, db
) -> None:
    capped = await _seed_remnawave_user(db, name='rw-capped', hwid_device_limit=1)
    first = await client.post(f'/pub/u/{capped.public_token}/devices', json={'name': 'phone'})
    assert first.status_code == HTTPStatus.CREATED
    second = await client.post(f'/pub/u/{capped.public_token}/devices', json={'name': 'laptop'})
    assert second.status_code == HTTPStatus.CONFLICT

    freed = await client.delete(f'/pub/u/{capped.public_token}/devices/{first.json()["id"]}')
    assert freed.status_code == HTTPStatus.OK
    assert freed.json()['device_count'] == 0
    again = await client.post(f'/pub/u/{capped.public_token}/devices', json={'name': 'laptop'})
    assert again.status_code == HTTPStatus.CREATED

    unlimited = await _seed_remnawave_user(db, name='rw-unlimited', hwid_device_limit=0)
    for expected_name in ('one', 'two'):
        resp = await client.post(
            f'/pub/u/{unlimited.public_token}/devices', json={'name': expected_name}
        )
        assert resp.status_code == HTTPStatus.CREATED


# ── delete ─────────────────────────────────────────────────────────────────────


async def test_delete_device_is_idempotent_and_frees_the_slot_immediately(
    client: AsyncClient, db, sync_enqueues: list[dict]
) -> None:
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='deleter', device_limit=1)
    added = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'laptop'})
    device_id = added.json()['id']
    sync_enqueues.clear()

    first = await client.delete(f'/pub/u/{user.public_token}/devices/{device_id}')

    assert first.status_code == HTTPStatus.OK
    body = first.json()
    assert body['id'] == device_id
    assert body['status'] == 'deleting'
    assert body['deleted_at'] is not None
    assert body['device_count'] == 0
    assert [call['node_id'] for call in sync_enqueues] == ['node-1']

    device = await db.get(Device, device_id)
    await db.refresh(device)
    assert device.deleted_at is not None
    peer = ((await db.execute(select(Peer).where(Peer.device_id == device_id))).scalars().all())[0]
    assert peer.status == 'pending_delete'
    # The identity and history stay: deletion is a tombstone, not a row delete.
    assert device.private_key
    assert device.vpn_ip

    second = await client.delete(f'/pub/u/{user.public_token}/devices/{device_id}')
    assert second.status_code == HTTPStatus.OK
    assert second.json()['device_count'] == 0

    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    assert info['devices'] == []
    assert info['device_count'] == 0
    assert info['can_add_device'] is True


async def test_delete_device_is_scoped_to_the_owner(client: AsyncClient, db) -> None:
    owner = await _seed_user(db, name='owner')
    other = await _seed_user(db, name='other')
    added = await client.post(f'/pub/u/{owner.public_token}/devices', json={'name': 'laptop'})
    device_id = added.json()['id']

    for resp in (
        await client.delete(f'/pub/u/{other.public_token}/devices/{device_id}'),
        await client.delete(f'/pub/u/{other.public_token}/devices/missing'),
        await client.delete('/pub/u/no-such-token/devices/missing'),
    ):
        assert resp.status_code == HTTPStatus.NOT_FOUND

    device = await db.get(Device, device_id)
    await db.refresh(device)
    assert device.deleted_at is None


async def test_a_released_address_returns_to_the_pool_only_after_the_last_ack(
    client: AsyncClient, db, worker_headers
) -> None:
    """Repeated deletion must never exhaust the finite subnet: a confirmed removal frees the IP."""
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='pool')

    first_id = (
        await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'one'})
    ).json()['id']
    first = await db.get(Device, first_id)
    assert first is not None
    first_ip = first.vpn_ip
    deleted = await client.delete(f'/pub/u/{user.public_token}/devices/{first_id}')
    assert deleted.status_code == HTTPStatus.OK

    # the node has not confirmed the removal yet: the address must stay out of the pool
    second_id = (
        await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'two'})
    ).json()['id']
    second = await db.get(Device, second_id)
    assert second is not None
    assert second.vpn_ip != first_ip

    # the node's result no longer lists the deleted device's peer: removal is confirmed
    ack = await client.post(
        '/internal/worker/nodes/node-1/sync-result',
        json={'ok': True, 'peers': []},
        headers=worker_headers,
    )
    assert ack.status_code == HTTPStatus.OK

    await db.refresh(first)
    assert first.vpn_ip is None
    assert first.released_vpn_ip == first_ip
    assert first.ip_released_at is not None
    # only the address moved: identity, key material and the peer row stay for accounting
    assert first.deleted_at is not None
    assert first.public_key
    assert first.private_key
    peer = (await db.execute(select(Peer).where(Peer.device_id == first_id))).scalar_one()
    assert peer.status == 'deleted'
    assert peer.psk_key

    third_id = (
        await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'three'})
    ).json()['id']
    third = await db.get(Device, third_id)
    assert third is not None
    assert third.vpn_ip == first_ip


async def test_an_exhausted_address_pool_is_a_controlled_503_not_a_500(
    client: AsyncClient, db, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full pool - live devices or removals an unreachable node never confirmed - is not a bug."""
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='full')

    def _exhausted(_used: set[str]) -> str:
        raise RuntimeError('VPN subnet 10.8.0.0/24 is exhausted')

    monkeypatch.setattr('app.services.devices.allocate_ip', _exhausted)

    resp = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'one'})

    assert resp.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert 'exhausted' in resp.json()['detail']
    assert (await db.execute(select(Device).where(Device.user_id == user.id))).scalars().all() == []


async def test_deleted_device_never_serves_config_after_a_stale_node_reply(
    client: AsyncClient, db, worker_headers
) -> None:
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='stale')
    added = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'laptop'})
    device_id = added.json()['id']
    device = await db.get(Device, device_id)

    await _ack_peer(client, worker_headers, 'node-1', device.public_key)
    config_url = f'/pub/u/{user.public_token}/devices/{device_id}/config/awg/node-1'
    assert (await client.get(config_url)).status_code == HTTPStatus.OK

    assert (await client.delete(f'/pub/u/{user.public_token}/devices/{device_id}')).status_code == (
        HTTPStatus.OK
    )

    # A reply produced before the deletion must not resurrect the peer or the config.
    await _ack_peer(client, worker_headers, 'node-1', device.public_key)

    saved_peer = (await db.execute(select(Peer).where(Peer.device_id == device_id))).scalars().one()
    await db.refresh(saved_peer)
    assert saved_peer.status == 'pending_delete'
    assert (await client.get(config_url)).status_code == HTTPStatus.NOT_FOUND
    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    assert info['devices'] == []


# ── device downloads and readiness ─────────────────────────────────────────────


async def test_device_downloads_wait_for_the_node_ack(
    client: AsyncClient, db, worker_headers
) -> None:
    await _seed_node(db, 'node-1', 'node-1', **NODE_METADATA)
    await _seed_node(
        db, 'node-2', 'node-2', server_public_key='node-2-public', server_endpoint='vpn2:51820'
    )
    user = await _seed_user(db, name='readiness')
    added = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'laptop'})
    device_id = added.json()['id']
    device = await db.get(Device, device_id)
    base = f'/pub/u/{user.public_token}/devices/{device_id}'

    # Pending: every route refuses with 503 instead of an empty/PSK-less config.
    for path in (
        f'{base}/config/awg/node-1',
        f'{base}/config/vpn/node-1',
        f'{base}/qr/awg/node-1',
        f'{base}/qr/vpn/node-1',
        f'{base}/qr-chunks/vpn/node-1',
    ):
        assert (await client.get(path)).status_code == HTTPStatus.SERVICE_UNAVAILABLE

    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    assert [node['status'] for node in info['devices'][0]['nodes']] == ['pending', 'pending']

    await _ack_peer(client, worker_headers, 'node-1', device.public_key)

    peer = (
        (
            await db.execute(
                select(Peer).where(Peer.device_id == device_id, Peer.node_id == 'node-1')
            )
        )
        .scalars()
        .one()
    )
    await db.refresh(peer)
    assert peer.status == 'active'

    config = await client.get(f'{base}/config/awg/node-1')
    assert config.status_code == HTTPStatus.OK
    assert f'PrivateKey = {device.private_key}' in config.text
    assert f'Address = {device.vpn_ip}/32' in config.text
    assert f'PresharedKey = {peer.psk_key}' in config.text
    assert config.headers['content-disposition'].startswith('attachment; filename=')
    vpn_config = await client.get(f'{base}/config/vpn/node-1')
    assert vpn_config.status_code == HTTPStatus.OK
    assert vpn_config.headers['content-type'] == 'application/octet-stream'
    assert (await client.get(f'{base}/qr/awg/node-1')).status_code == HTTPStatus.OK
    assert (await client.get(f'{base}/qr/vpn/node-1')).status_code == HTTPStatus.OK
    chunks = await client.get(f'{base}/qr-chunks/vpn/node-1')
    assert chunks.status_code == HTTPStatus.OK
    assert chunks.json()['chunks']

    # The other server is independent: no waiting for it, and no config without its own ack.
    assert (await client.get(f'{base}/config/awg/node-2')).status_code == (
        HTTPStatus.SERVICE_UNAVAILABLE
    )
    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    nodes = info['devices'][0]['nodes']
    assert nodes[0]['status'] == 'ready'
    assert nodes[0]['ready'] is True
    assert nodes[0]['vpn_uri'].startswith('vpn://')
    assert nodes[1]['status'] == 'pending'
    assert nodes[1]['ready'] is False
    assert nodes[1]['vpn_uri'] is None


async def test_failed_sync_reports_error_for_a_pending_peer_and_keeps_forms_unavailable(
    client: AsyncClient, db, worker_headers
) -> None:
    """A failed sync is a diagnostic: an unapplied peer reads as ``error``, never as usable."""
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='failed-pending')
    added = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'laptop'})
    device_id = added.json()['id']
    base = f'/pub/u/{user.public_token}/devices/{device_id}'

    await _fail_node_sync(client, worker_headers, 'node-1')

    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    entry = info['devices'][0]['nodes'][0]
    assert entry['status'] == 'error'
    assert entry['ready'] is False
    assert entry['vpn_uri'] is None
    assert info['devices'][0]['status'] == 'error'

    for path in DOWNLOAD_PATHS:
        assert (await client.get(f'{base}/{path}')).status_code == HTTPStatus.SERVICE_UNAVAILABLE


async def test_acked_peer_stays_downloadable_after_a_later_failed_sync(
    client: AsyncClient, db, worker_headers
) -> None:
    """Availability is independent of the sync diagnostic: an acked peer keeps serving on failure.

    The peer, the device credentials and the cached node metadata are all still on record, so the
    node's later failed sync is reported as ``error`` while every download keeps working.
    """
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='failed-active')
    added = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'laptop'})
    device_id = added.json()['id']
    device = await db.get(Device, device_id)
    base = f'/pub/u/{user.public_token}/devices/{device_id}'
    await _ack_peer(client, worker_headers, 'node-1', device.public_key)

    await _fail_node_sync(client, worker_headers, 'node-1')

    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    entry = info['devices'][0]['nodes'][0]
    # the failure stays visible as a diagnostic ...
    assert entry['status'] == 'error'
    # ... while the acknowledged peer keeps the device usable, aggregate included
    assert entry['ready'] is True
    assert entry['vpn_uri'].startswith('vpn://')
    assert info['devices'][0]['status'] == 'ready'

    for path in DOWNLOAD_PATHS:
        assert (await client.get(f'{base}/{path}')).status_code == HTTPStatus.OK


async def test_failed_sync_does_not_relax_the_account_guard_or_deletion(
    client: AsyncClient, db, worker_headers
) -> None:
    """A failed node sync never turns a usable device into a way around the account state."""
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='failed-guard')
    added = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'laptop'})
    device_id = added.json()['id']
    device = await db.get(Device, device_id)
    base = f'/pub/u/{user.public_token}/devices/{device_id}'
    await _ack_peer(client, worker_headers, 'node-1', device.public_key)
    await _fail_node_sync(client, worker_headers, 'node-1')

    user.is_blocked = True
    await db.commit()

    for path in DOWNLOAD_PATHS:
        assert (await client.get(f'{base}/{path}')).status_code == HTTPStatus.FORBIDDEN

    revoked = await client.delete(f'/pub/u/{user.public_token}/devices/{device_id}')
    assert revoked.status_code == HTTPStatus.OK
    assert revoked.json()['status'] == 'deleting'


async def test_legacy_alias_availability_tracks_the_failed_sync_independently(
    client: AsyncClient, db, worker_headers
) -> None:
    """The migration ``Default`` alias answers from the same split diagnostic/availability state."""
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='failed-legacy')
    device = await _seed_legacy_default(db, user)
    node = await db.get(Node, 'node-1')
    peer = await _seed_peer(db, node=node, device=device, status='pending')
    base = f'/pub/u/{user.public_token}'

    await _fail_node_sync(client, worker_headers, 'node-1')

    info = (await client.get(f'{base}/info')).json()
    assert info['nodes'][0]['status'] == 'error'
    assert info['nodes'][0]['ready'] is False
    assert info['nodes'][0]['vpn_uri'] is None
    for path in DOWNLOAD_PATHS:
        assert (await client.get(f'{base}/{path}')).status_code == HTTPStatus.SERVICE_UNAVAILABLE

    # the peer is applied (as an earlier successful sync would have left it) and keeps serving
    peer.status = 'active'
    await db.commit()

    info = (await client.get(f'{base}/info')).json()
    assert info['nodes'][0]['status'] == 'error'
    assert info['nodes'][0]['ready'] is True
    assert info['nodes'][0]['vpn_uri'].startswith('vpn://')
    for path in DOWNLOAD_PATHS:
        assert (await client.get(f'{base}/{path}')).status_code == HTTPStatus.OK


async def test_device_downloads_are_scoped_to_the_owner(
    client: AsyncClient, db, worker_headers
) -> None:
    await _seed_node(db, **NODE_METADATA)
    owner = await _seed_user(db, name='owner-dl')
    other = await _seed_user(db, name='other-dl')
    added = await client.post(f'/pub/u/{owner.public_token}/devices', json={'name': 'laptop'})
    device_id = added.json()['id']
    device = await db.get(Device, device_id)
    await _ack_peer(client, worker_headers, 'node-1', device.public_key)

    for path in (
        'config/awg/node-1',
        'config/vpn/node-1',
        'qr/awg/node-1',
        'qr/vpn/node-1',
        'qr-chunks/vpn/node-1',
    ):
        denied = await client.get(f'/pub/u/{other.public_token}/devices/{device_id}/{path}')
        assert denied.status_code == HTTPStatus.NOT_FOUND
        unknown_node = await client.get(
            f'/pub/u/{other.public_token}/devices/{device_id}/config/awg/nope'
        )
        assert unknown_node.status_code == HTTPStatus.NOT_FOUND
        ok = await client.get(f'/pub/u/{owner.public_token}/devices/{device_id}/{path}')
        assert ok.status_code == HTTPStatus.OK

    missing_device = await client.get(
        f'/pub/u/{owner.public_token}/devices/missing/config/awg/node-1'
    )
    assert missing_device.status_code == HTTPStatus.NOT_FOUND
    missing_node = await client.get(
        f'/pub/u/{owner.public_token}/devices/{device_id}/config/awg/nope'
    )
    assert missing_node.status_code == HTTPStatus.NOT_FOUND


# ── legacy routes ──────────────────────────────────────────────────────────────


async def test_legacy_downloads_keep_the_migration_credentials(client: AsyncClient, db) -> None:
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(
        db,
        name='legacy-dl',
        public_key='alice-public',
        private_key='alice-private',
        vpn_ip='10.8.0.2',
    )
    device = await _seed_legacy_default(db, user)
    await _seed_peer(db, node=await db.get(Node, 'node-1'), device=device, psk_key='legacy-psk')

    config = await client.get(f'/pub/u/{user.public_token}/config/awg/node-1')

    assert config.status_code == HTTPStatus.OK
    assert 'PrivateKey = alice-private' in config.text
    assert 'Address = 10.8.0.2/32' in config.text
    assert 'PresharedKey = legacy-psk' in config.text
    assert (await client.get(f'/pub/u/{user.public_token}/config/vpn/node-1')).status_code == (
        HTTPStatus.OK
    )
    assert (await client.get(f'/pub/u/{user.public_token}/qr/awg/node-1')).status_code == (
        HTTPStatus.OK
    )
    assert (await client.get(f'/pub/u/{user.public_token}/qr/vpn/node-1')).status_code == (
        HTTPStatus.OK
    )
    chunks = await client.get(f'/pub/u/{user.public_token}/qr-chunks/vpn/node-1')
    assert chunks.status_code == HTTPStatus.OK
    assert chunks.json()['chunks']


async def test_legacy_downloads_404_without_a_live_default(client: AsyncClient, db) -> None:
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='no-default')
    other = Device(
        id='other-device',
        user_id=user.id,
        name='laptop',
        public_key='other-public',
        private_key='other-private',
        vpn_ip='10.8.0.8',
    )
    db.add(other)
    await db.flush()
    await _seed_peer(db, node=await db.get(Node, 'node-1'), device=other)

    for path in (
        'config/awg/node-1',
        'config/vpn/node-1',
        'qr/awg/node-1',
        'qr/vpn/node-1',
        'qr-chunks/vpn/node-1',
    ):
        resp = await client.get(f'/pub/u/{user.public_token}/{path}')
        assert resp.status_code == HTTPStatus.NOT_FOUND

    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    assert info['nodes'] == []
    assert [device['name'] for device in info['devices']] == ['laptop']


async def test_legacy_downloads_404_when_the_default_was_deleted(client: AsyncClient, db) -> None:
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='deleted-default')
    device = await _seed_legacy_default(db, user)
    await _seed_peer(db, node=await db.get(Node, 'node-1'), device=device)
    assert (await client.delete(f'/pub/u/{user.public_token}/devices/{device.id}')).status_code == (
        HTTPStatus.OK
    )

    assert (await client.get(f'/pub/u/{user.public_token}/config/awg/node-1')).status_code == (
        HTTPStatus.NOT_FOUND
    )
    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    assert info['nodes'] == []
    assert info['devices'] == []


async def test_legacy_downloads_stay_pending_without_an_active_peer(
    client: AsyncClient, db
) -> None:
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='pending-legacy')
    device = await _seed_legacy_default(db, user)
    await _seed_peer(db, node=await db.get(Node, 'node-1'), device=device, status='pending')

    resp = await client.get(f'/pub/u/{user.public_token}/config/awg/node-1')

    assert resp.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    assert info['nodes'][0]['ready'] is False
    assert info['nodes'][0]['vpn_uri'] is None


async def test_download_filenames_escape_quotes_slashes_and_unicode(
    client: AsyncClient, db, worker_headers
) -> None:
    node = await _seed_node(
        db,
        'node-1',
        'edge "eu"/1',
        server_public_key='node-public',
        server_endpoint='vpn.example:51820',
    )
    user = await _seed_user(db, name='files')
    added = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'Ноутбук'})
    device_id = added.json()['id']
    device = await db.get(Device, device_id)
    await _ack_peer(client, worker_headers, node.id, device.public_key)

    resp = await client.get(f'/pub/u/{user.public_token}/devices/{device_id}/config/awg/{node.id}')

    assert resp.status_code == HTTPStatus.OK
    disposition = resp.headers['content-disposition']
    assert "filename*=UTF-8''" in disposition
    fallback = disposition.split('filename="', 1)[1].split('"', 1)[0]
    assert '"' not in fallback
    assert '/' not in fallback
    assert '\n' not in disposition


# ── status guard ───────────────────────────────────────────────────────────────


async def test_blocked_account_is_denied_downloads_but_may_revoke_its_devices(
    client: AsyncClient, db
) -> None:
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(
        db,
        name='blocked-owner',
        public_key='alice-public',
        private_key='alice-private',
        vpn_ip='10.8.0.2',
        is_blocked=True,
    )
    default_device = await _seed_legacy_default(db, user)
    node = await db.get(Node, 'node-1')
    await _seed_peer(db, node=node, device=default_device)
    added = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'laptop'})
    assert added.status_code == HTTPStatus.FORBIDDEN

    for path in (
        'config/awg/node-1',
        'config/vpn/node-1',
        'qr/awg/node-1',
        'qr/vpn/node-1',
        'qr-chunks/vpn/node-1',
    ):
        resp = await client.get(f'/pub/u/{user.public_token}/{path}')
        assert resp.status_code == HTTPStatus.FORBIDDEN

    default_download = await client.get(
        f'/pub/u/{user.public_token}/devices/{default_device.id}/config/awg/node-1'
    )
    assert default_download.status_code == HTTPStatus.FORBIDDEN

    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    assert info['blocked'] is True
    assert info['can_add_device'] is False
    assert info['nodes'] == []
    assert info['device_count'] == 1
    # The owner still recognises the device it owns: safe metadata only, so the page can offer its
    # deletion. Nothing usable is exposed - every readiness flag is off and no configuration URL or
    # key material appears anywhere in the payload.
    assert [device['name'] for device in info['devices']] == ['Default']
    listed = info['devices'][0]
    assert set(listed) == {'id', 'name', 'created_at', 'status', 'nodes'}
    assert set(listed['nodes'][0]) == {'id', 'name', 'status', 'ready', 'vpn_uri'}
    assert listed['nodes'][0]['ready'] is False
    assert listed['nodes'][0]['vpn_uri'] is None

    revoked = await client.delete(f'/pub/u/{user.public_token}/devices/{default_device.id}')

    assert revoked.status_code == HTTPStatus.OK
    assert revoked.json()['status'] == 'deleting'

    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    assert info['blocked'] is True
    assert info['nodes'] == []
    assert info['devices'] == []
    assert info['device_count'] == 0
    assert info['can_add_device'] is False


@pytest.mark.parametrize('status', ['LIMITED', 'DISABLED', 'EXPIRED'])
async def test_remnawave_status_is_denied_downloads_and_adds(
    client: AsyncClient, db, status: str
) -> None:
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_remnawave_user(db, name=f'rw-{status.lower()}', status=status)
    device = await _seed_legacy_default(db, user)
    await _seed_peer(db, node=await db.get(Node, 'node-1'), device=device)

    assert (await client.get(f'/pub/u/{user.public_token}/config/awg/node-1')).status_code == (
        HTTPStatus.FORBIDDEN
    )
    assert (
        await client.get(f'/pub/u/{user.public_token}/devices/{device.id}/config/awg/node-1')
    ).status_code == HTTPStatus.FORBIDDEN
    add = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'laptop'})
    assert add.status_code == HTTPStatus.FORBIDDEN


async def test_expired_remnawave_account_is_denied_downloads(client: AsyncClient, db) -> None:
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_remnawave_user(
        db, name='rw-past', expire_at=datetime.now(UTC) - timedelta(days=1)
    )
    device = await _seed_legacy_default(db, user)
    await _seed_peer(db, node=await db.get(Node, 'node-1'), device=device)

    resp = await client.get(f'/pub/u/{user.public_token}/config/awg/node-1')

    assert resp.status_code == HTTPStatus.FORBIDDEN
    info = (await client.get(f'/pub/u/{user.public_token}/info')).json()
    assert info['status'] == {'code': 'expired', 'reason': 'expired'}
    assert info['devices'][0]['nodes'][0]['vpn_uri'] is None


async def test_regenerated_public_token_invalidates_the_old_one(
    client: AsyncClient, db, auth_headers, worker_headers
) -> None:
    await _seed_node(db, **NODE_METADATA)
    user = await _seed_user(db, name='rotating')
    added = await client.post(f'/pub/u/{user.public_token}/devices', json={'name': 'laptop'})
    device_id = added.json()['id']
    device = await db.get(Device, device_id)
    await _ack_peer(client, worker_headers, 'node-1', device.public_key)
    old_token = user.public_token
    config_url = f'/pub/u/{old_token}/devices/{device_id}/config/awg/node-1'
    assert (await client.get(config_url)).status_code == HTTPStatus.OK

    rotated = await client.post(
        f'/api/users/{user.id}/public-link/regenerate', headers=auth_headers
    )

    assert rotated.status_code == HTTPStatus.OK
    new_token = rotated.json()['public_token']
    assert new_token != old_token
    assert (await client.get(f'/pub/u/{old_token}/info')).status_code == HTTPStatus.NOT_FOUND
    assert (
        await client.post(f'/pub/u/{old_token}/devices', json={'name': 'laptop'})
    ).status_code == HTTPStatus.NOT_FOUND
    assert (await client.get(config_url)).status_code == HTTPStatus.NOT_FOUND
    assert (await client.get(f'/pub/u/{new_token}/info')).status_code == HTTPStatus.OK
    assert (
        await client.get(f'/pub/u/{new_token}/devices/{device_id}/config/awg/node-1')
    ).status_code == HTTPStatus.OK
