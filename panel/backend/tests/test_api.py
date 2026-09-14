import asyncio
from datetime import UTC, date, datetime, timedelta
from http import HTTPStatus
from unittest.mock import ANY, AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.models import (
    AsyncOperation,
    Device,
    LocalAmneziawgTrafficSettings,
    LocalAmneziawgUserDailyTraffic,
    LocalAmneziawgUserLifetimeTraffic,
    LocalAmneziawgUserNodeDailyTraffic,
    LocalAmneziawgUserNodeLifetimeTraffic,
    Node,
    Peer,
    RemnawaveUser,
    User,
)
from app.services.devices import create_device, delete_device


@pytest.fixture(autouse=True)
def _mock_job_producer():
    """Mock RabbitMQ producers so API tests don't need a live broker."""

    async def _sync_all(**kwargs):
        return {'command': 'sync_all', 'operation_id': kwargs['operation_id']}

    async def _sync_node(node_id, **kwargs):
        return {
            'command': 'sync_node',
            'target_id': node_id,
            'operation_id': kwargs['operation_id'],
        }

    async def _provision_node(node_id, **kwargs):
        return {
            'command': 'provision_node',
            'target_id': node_id,
            'operation_id': kwargs['operation_id'],
        }

    async def _cleanup_raw_traffic_samples(**kwargs):
        return {
            'command': 'cleanup_raw_traffic_samples',
            'operation_id': kwargs['operation_id'],
        }

    async def _remnawave_full_reconcile(**kwargs):
        return {
            'command': 'remnawave_full_reconcile',
            'operation_id': kwargs['operation_id'],
        }

    async def _remnawave_sync_user(user_uuid, **kwargs):
        return {
            'command': 'remnawave_sync_user',
            'target_id': user_uuid,
            'operation_id': kwargs['operation_id'],
        }

    async def _remnawave_disable_user(user_uuid, **kwargs):
        return {
            'command': 'remnawave_disable_user',
            'target_id': user_uuid,
            'operation_id': kwargs['operation_id'],
        }

    with (
        patch('app.routers.api.enqueue_sync_all', new=AsyncMock(side_effect=_sync_all)),
        patch('app.routers.api.enqueue_sync_node', new=AsyncMock(side_effect=_sync_node)),
        patch(
            'app.routers.api.enqueue_provision_node',
            new=AsyncMock(side_effect=_provision_node),
        ),
        patch(
            'app.routers.api.enqueue_cleanup_raw_traffic_samples',
            new=AsyncMock(side_effect=_cleanup_raw_traffic_samples),
        ),
        patch(
            'app.routers.api.enqueue_remnawave_full_reconcile',
            new=AsyncMock(side_effect=_remnawave_full_reconcile),
        ),
        patch(
            'app.routers.api.enqueue_remnawave_sync_user',
            new=AsyncMock(side_effect=_remnawave_sync_user),
        ),
        patch(
            'app.routers.api.enqueue_remnawave_disable_user',
            new=AsyncMock(side_effect=_remnawave_disable_user),
        ),
    ):
        yield


# ── Nodes ──────────────────────────────────────────────────────────────────────


async def test_list_nodes_empty(client: AsyncClient, auth_headers):
    headers = auth_headers
    resp = await client.get('/api/nodes', headers=headers)
    assert resp.status_code == HTTPStatus.OK
    assert resp.json() == []


async def test_add_node(client: AsyncClient, auth_headers):
    headers = auth_headers
    resp = await client.post(
        '/api/nodes',
        json={'name': 'node-1', 'url': 'http://agent:8000', 'token': 'tok'},
        headers=headers,
    )
    assert resp.status_code == HTTPStatus.CREATED
    data = resp.json()
    assert data['name'] == 'node-1'
    assert data['url'] == 'http://agent:8000'
    assert data['server_public_key'] is not None
    assert data['listen_port'] == 51820


async def test_add_node_creates_peers_for_existing_devices(client: AsyncClient, auth_headers, db):
    """A new node provisions peers for live devices only (users own devices, not keypairs)."""
    headers = auth_headers
    user_resp = await client.post('/api/users', json={'name': 'alice'}, headers=headers)
    user_id = user_resp.json()['id']
    device, _ = await create_device(db, user_id, name='laptop')
    await db.commit()

    resp = await client.post(
        '/api/nodes',
        json={'name': 'node-2', 'url': 'http://agent2:8000', 'token': 'tok'},
        headers=headers,
    )
    assert resp.status_code == HTTPStatus.CREATED
    node_id = resp.json()['id']
    peers_resp = await client.get(f'/api/nodes/{node_id}/peers', headers=headers)
    assert peers_resp.status_code == HTTPStatus.OK
    assert len(peers_resp.json()) == 1
    assert peers_resp.json()[0]['user_name'] == 'alice'
    assert peers_resp.json()[0]['vpn_ip'] == device.vpn_ip
    assert peers_resp.json()[0]['online'] is False
    assert peers_resp.json()[0]['endpoint'] is None


async def test_add_node_creates_no_peers_for_device_less_users(client: AsyncClient, auth_headers):
    """New accounts own nothing: creating a node must not invent devices or peers."""
    headers = auth_headers
    await client.post('/api/users', json={'name': 'alice'}, headers=headers)

    resp = await client.post(
        '/api/nodes',
        json={'name': 'node-empty', 'url': 'http://agent-empty:8000', 'token': 'tok'},
        headers=headers,
    )
    assert resp.status_code == HTTPStatus.CREATED
    node_id = resp.json()['id']

    peers_resp = await client.get(f'/api/nodes/{node_id}/peers', headers=headers)
    assert peers_resp.json() == []


async def test_create_pending_peers_is_idempotent(client: AsyncClient, auth_headers, db):
    headers = auth_headers
    user_resp = await client.post('/api/users', json={'name': 'alice'}, headers=headers)
    user_id = user_resp.json()['id']
    node_resp = await client.post(
        '/api/nodes',
        json={'name': 'node-idem', 'url': 'http://agent-idem:8000', 'token': 'tok'},
        headers=headers,
    )
    node = await db.get(Node, node_resp.json()['id'])
    device, _ = await create_device(db, user_id, name='laptop')
    await db.commit()

    from app.services.devices import create_pending_peers_for_device, create_pending_peers_for_node

    await create_pending_peers_for_node(db, node)
    await create_pending_peers_for_device(db, device)
    await db.commit()

    peers = (
        (await db.execute(select(Peer).where(Peer.node_id == node.id, Peer.device_id == device.id)))
        .scalars()
        .all()
    )
    assert len(peers) == 1


async def test_create_pending_peers_for_device_is_concurrency_safe(db):
    node = Node(
        id='node-race',
        name='node-race',
        url='http://agent:8000',
        token='tok',  # noqa: S106
    )
    user = User(id='user-race', name='alice-race')
    device = Device(
        id='device-race',
        user_id=user.id,
        name='laptop',
        public_key='alice-race-public',
        private_key='alice-race-private',
        vpn_ip='10.8.0.2',
    )
    db.add_all([node, user, device])
    await db.commit()

    session_factory = async_sessionmaker(bind=db.bind, expire_on_commit=False)

    from app.services.devices import create_pending_peers_for_device

    async def create_once() -> set[str]:
        async with session_factory() as session:
            loaded_device = await session.get(Device, device.id)
            created = await create_pending_peers_for_device(session, loaded_device)
            await session.commit()
            return created

    first, second = await asyncio.gather(create_once(), create_once())

    peers = (
        (await db.execute(select(Peer).where(Peer.node_id == node.id, Peer.device_id == device.id)))
        .scalars()
        .all()
    )
    assert len(peers) == 1
    assert sorted([first, second], key=len) == [set(), {node.id}]


async def test_create_pending_peers_for_node_is_concurrency_safe(db):
    node = Node(
        id='node-race-2',
        name='node-race-2',
        url='http://agent:8000',
        token='tok',  # noqa: S106
    )
    user = User(id='user-race-2', name='alice-race-2')
    device = Device(
        id='device-race-2',
        user_id=user.id,
        name='laptop',
        public_key='alice-race-2-public',
        private_key='alice-race-2-private',
        vpn_ip='10.8.0.3',
    )
    db.add_all([node, user, device])
    await db.commit()

    session_factory = async_sessionmaker(bind=db.bind, expire_on_commit=False)

    from app.services.devices import create_pending_peers_for_node

    async def create_once() -> set[str]:
        async with session_factory() as session:
            loaded_node = await session.get(Node, node.id)
            created = await create_pending_peers_for_node(session, loaded_node)
            await session.commit()
            return created

    first, second = await asyncio.gather(create_once(), create_once())

    peers = (
        (await db.execute(select(Peer).where(Peer.node_id == node.id, Peer.device_id == device.id)))
        .scalars()
        .all()
    )
    assert len(peers) == 1
    assert sorted([first, second], key=len) == [set(), {device.id}]


async def test_list_nodes_after_create(client: AsyncClient, auth_headers):
    headers = auth_headers
    # Create a node in this same test (DB is reset between tests)
    await client.post(
        '/api/nodes',
        json={'name': 'n-list', 'url': 'http://agent:8000', 'token': 'tok'},
        headers=headers,
    )
    resp = await client.get('/api/nodes', headers=headers)
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    assert len(data) >= 1
    for node in data:
        assert 'online' in node
        assert 'online_peers_count' in node
        assert node['online_threshold_seconds'] == 180
    # Should have our just-created node
    assert any(n['name'] == 'n-list' for n in data)


async def test_list_nodes_online_uses_heartbeat_reachability(client: AsyncClient, auth_headers, db):
    node = Node(
        id='reachable-node',
        name='reachable-node',
        url='http://agent:8000',
        token='tok',  # noqa: S106
        health_status='offline',
        reachability_status='reachable',
    )
    db.add(node)
    await db.commit()

    resp = await client.get('/api/nodes', headers=auth_headers)

    assert resp.status_code == HTTPStatus.OK
    listed = next(item for item in resp.json() if item['id'] == 'reachable-node')
    assert listed['online'] is True
    assert listed['reachable'] is True


async def test_list_operations_exposes_resolution_state(client: AsyncClient, auth_headers, db):
    failed = AsyncOperation(
        id='op-failed',
        kind='sync_node',
        target_type='node',
        target_id='node-1',
        status='failed',
        error='node-agent unavailable',
        idempotency_key='failed-key',
    )
    timed_out = AsyncOperation(
        id='op-timeout',
        kind='provision_node',
        target_type='node',
        target_id='node-2',
        status='failed_by_timeout',
        error='Operation exceeded running timeout and needs manual action',
        idempotency_key='timeout-key',
    )
    db.add_all([failed, timed_out])
    await db.commit()

    resp = await client.get('/api/operations', headers=auth_headers)

    assert resp.status_code == HTTPStatus.OK
    data = {item['id']: item for item in resp.json()}
    assert data['op-failed']['resolution_state'] == 'recoverable'
    assert data['op-failed']['can_retry'] is True
    assert data['op-timeout']['resolution_state'] == 'needs_manual_action'
    assert data['op-timeout']['can_retry'] is True


async def test_retry_failed_operation_creates_new_operation(client: AsyncClient, auth_headers, db):
    operation = AsyncOperation(
        id='retry-source',
        kind='sync_node',
        target_type='node',
        target_id='node-1',
        status='failed_by_timeout',
        error='Operation exceeded running timeout and needs manual action',
        idempotency_key='retry-source-key',
    )
    db.add(operation)
    await db.commit()

    resp = await client.post('/api/operations/retry-source/retry', headers=auth_headers)

    assert resp.status_code == HTTPStatus.ACCEPTED
    payload = resp.json()
    retried = await db.get(AsyncOperation, payload['operation_id'])
    assert retried is not None
    assert retried.id != operation.id
    assert retried.kind == 'sync_node'
    assert retried.target_id == 'node-1'
    assert retried.status == 'queued'


async def test_update_node(client: AsyncClient, auth_headers):
    headers = auth_headers
    create_resp = await client.post(
        '/api/nodes',
        json={'name': 'node-update', 'url': 'http://agent:8000', 'token': 'tok'},
        headers=headers,
    )
    node_id = create_resp.json()['id']

    resp = await client.patch(
        f'/api/nodes/{node_id}',
        json={'jc': 10, 'jmin': 50, 'jmax': 100},
        headers=headers,
    )
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()['jc'] == 10


async def test_update_nonexistent_node(client: AsyncClient, auth_headers):
    headers = auth_headers
    resp = await client.patch(
        '/api/nodes/nonexistent-id',
        json={'jc': 10},
        headers=headers,
    )
    assert resp.status_code == HTTPStatus.NOT_FOUND


async def test_delete_node(client: AsyncClient, auth_headers):
    headers = auth_headers
    create_resp = await client.post(
        '/api/nodes',
        json={'name': 'node-delete', 'url': 'http://agent:8000', 'token': 'tok'},
        headers=headers,
    )
    node_id = create_resp.json()['id']

    resp = await client.delete(f'/api/nodes/{node_id}', headers=headers)
    assert resp.status_code == HTTPStatus.NO_CONTENT

    list_resp = await client.get('/api/nodes', headers=headers)
    assert all(n['id'] != node_id for n in list_resp.json())


async def test_delete_nonexistent_node(client: AsyncClient, auth_headers):
    headers = auth_headers
    resp = await client.delete('/api/nodes/nonexistent-id', headers=headers)
    assert resp.status_code == HTTPStatus.NOT_FOUND


async def test_provision_node(client: AsyncClient, auth_headers):
    headers = auth_headers
    create_resp = await client.post(
        '/api/nodes',
        json={'name': 'node-prov', 'url': 'http://agent:8000', 'token': 'tok'},
        headers=headers,
    )
    node_id = create_resp.json()['id']
    resp = await client.post(f'/api/nodes/{node_id}/provision', headers=headers)
    assert resp.status_code == HTTPStatus.ACCEPTED
    data = resp.json()
    assert data['operation_id']
    assert data['status_url'] == f'/api/operations/{data["operation_id"]}'


async def test_add_node_marks_provision_failed_when_enqueue_fails(
    client: AsyncClient,
    auth_headers,
    db,
):
    headers = auth_headers
    with patch(
        'app.routers.api.enqueue_provision_node',
        new=AsyncMock(side_effect=RuntimeError('rabbitmq unavailable')),
    ):
        resp = await client.post(
            '/api/nodes',
            json={'name': 'node-enqueue-fail', 'url': 'http://agent:8000', 'token': 'tok'},
            headers=headers,
        )

    assert resp.status_code == HTTPStatus.CREATED
    data = resp.json()
    assert data['provision_status'] == 'failed'

    node = await db.get(Node, data['id'])
    assert node is not None
    assert node.provision_status == 'failed'
    assert node.last_error == 'rabbitmq unavailable'


# ── Users ──────────────────────────────────────────────────────────────────────


async def test_list_users_empty(client: AsyncClient, auth_headers):
    headers = auth_headers
    resp = await client.get('/api/users', headers=headers)
    assert resp.status_code == HTTPStatus.OK
    assert resp.json() == []


async def test_add_user(client: AsyncClient, auth_headers):
    headers = auth_headers
    resp = await client.post('/api/users', json={'name': 'bob'}, headers=headers)
    assert resp.status_code == HTTPStatus.CREATED
    data = resp.json()
    assert data['name'] == 'bob'
    # an account owns nothing until a device is added: no legacy keypair, no implicit device
    assert data['public_key'] is None
    assert data['vpn_ip'] is None
    assert not data['is_blocked']


async def test_add_user_with_name(client: AsyncClient, auth_headers):
    """Verify user is created with correct fields."""
    headers = auth_headers
    resp = await client.post('/api/users', json={'name': 'test-name'}, headers=headers)
    assert resp.status_code == HTTPStatus.CREATED
    data = resp.json()
    assert data['name'] == 'test-name'
    assert data['public_key'] is None
    assert data['vpn_ip'] is None
    assert data['is_blocked'] is False


async def test_list_users_with_peers(client: AsyncClient, auth_headers, db):
    """Peers are listed per owner; the retained owner columns keep no key material."""
    headers = auth_headers
    node_resp = await client.post(
        '/api/nodes',
        json={'name': 'n1', 'url': 'http://agent:8000', 'token': 'tok'},
        headers=headers,
    )
    user_resp = await client.post('/api/users', json={'name': 'dave'}, headers=headers)
    device, node_ids = await create_device(db, user_resp.json()['id'], name='laptop')
    await db.commit()
    assert node_ids == {node_resp.json()['id']}

    resp = await client.get('/api/users', headers=headers)
    assert resp.status_code == HTTPStatus.OK
    users = resp.json()
    assert len(users) >= 1
    dave = next(u for u in users if u['name'] == 'dave')
    # the device owns the credentials; the frozen legacy user columns stay empty
    assert device.public_key is not None
    assert dave['public_key'] is None
    assert dave['vpn_ip'] is None
    assert dave['online'] is False
    assert len(dave['peers']) == 1
    assert dave['peers'][0]['node_name'] == 'n1'
    assert dave['peers'][0]['online'] is False
    assert dave['peers'][0]['endpoint'] is None


async def test_online_fields_are_derived_from_peer_handshake(client: AsyncClient, auth_headers, db):
    threshold_settings = await LocalAmneziawgTrafficSettings.get_settings(db)
    threshold_settings.peer_online_threshold_seconds = 600
    now = datetime.now(UTC)
    node = Node(id='online-node', name='online-node', url='http://agent:8000', token='tok')  # noqa: S106
    user = User(id='online-user', name='online-user')
    device = Device(
        id='online-device',
        user_id=user.id,
        name='Default',
        public_key='online-public',
        private_key='online-private',
        vpn_ip='10.8.0.7',
    )
    peer = Peer(
        id='online-peer',
        node_id=node.id,
        user_id=user.id,
        device_id=device.id,
        status='active',
        last_handshake=now - timedelta(seconds=60),
        endpoint='203.0.113.10:54321',
    )
    db.add_all([node, user, device, peer])
    await db.commit()

    users_resp = await client.get('/api/users', headers=auth_headers)
    nodes_resp = await client.get('/api/nodes', headers=auth_headers)
    peers_resp = await client.get(f'/api/nodes/{node.id}/peers', headers=auth_headers)

    assert users_resp.status_code == HTTPStatus.OK
    assert nodes_resp.status_code == HTTPStatus.OK
    assert peers_resp.status_code == HTTPStatus.OK
    listed_user = next(row for row in users_resp.json() if row['id'] == user.id)
    listed_node = next(row for row in nodes_resp.json() if row['id'] == node.id)
    assert listed_user['online'] is True
    assert listed_user['peers'][0]['online'] is True
    assert listed_user['peers'][0]['endpoint'] == '203.0.113.10:54321'
    assert listed_node['online_peers_count'] == 1
    assert listed_node['online_threshold_seconds'] == 600
    assert peers_resp.json()[0]['online'] is True
    assert peers_resp.json()[0]['endpoint'] == '203.0.113.10:54321'
    assert peers_resp.json()[0]['is_blocked'] is False


async def test_node_peers_expose_blocked_flag(client: AsyncClient, auth_headers, db):
    node = Node(id='blocked-node', name='blocked-node', url='http://agent:8000', token='tok')  # noqa: S106
    user = User(id='blocked-user', name='blocked-user', is_blocked=True)
    device = Device(
        id='blocked-device',
        user_id=user.id,
        name='Default',
        public_key='blocked-public',
        private_key='blocked-private',
        vpn_ip='10.8.0.9',
    )
    peer = Peer(
        id='blocked-peer',
        node_id=node.id,
        user_id=user.id,
        device_id=device.id,
        status='pending',
    )
    db.add_all([node, user, device, peer])
    await db.commit()

    resp = await client.get(f'/api/nodes/{node.id}/peers', headers=auth_headers)

    assert resp.status_code == HTTPStatus.OK
    assert resp.json() == [
        {
            'id': peer.id,
            'node_id': node.id,
            'user_id': user.id,
            'status': 'pending',
            'is_blocked': True,
            'created_at': ANY,
            'user_name': user.name,
            'node_name': node.name,
            # the peer is keyed by its device: the row carries the device identity, not only the
            # owner, because one owner can hold several devices on the same node
            'device_id': device.id,
            'device_name': device.name,
            # the node peer reports the device's IP, not the frozen legacy user column
            'vpn_ip': device.vpn_ip,
            'endpoint': None,
            'last_handshake': None,
            'online': False,
        }
    ]


async def test_online_fields_tolerate_duplicate_settings_rows(
    client: AsyncClient, auth_headers, db
):
    db.add_all(
        [
            LocalAmneziawgTrafficSettings(peer_online_threshold_seconds=120),
            LocalAmneziawgTrafficSettings(peer_online_threshold_seconds=240),
        ]
    )
    await db.commit()

    users_resp = await client.get('/api/users', headers=auth_headers)
    nodes_resp = await client.get('/api/nodes', headers=auth_headers)

    assert users_resp.status_code == HTTPStatus.OK
    assert nodes_resp.status_code == HTTPStatus.OK


async def test_list_users_includes_local_traffic_summary(client: AsyncClient, auth_headers, db):
    headers = auth_headers
    user_resp = await client.post('/api/users', json={'name': 'local-list'}, headers=headers)
    user_id = user_resp.json()['id']
    updated_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    db.add(
        LocalAmneziawgUserLifetimeTraffic(
            user_id=user_id,
            rx_bytes=120,
            tx_bytes=80,
            total_bytes=200,
            updated_at=updated_at,
        )
    )
    await db.commit()

    resp = await client.get('/api/users', headers=headers)

    assert resp.status_code == HTTPStatus.OK
    user = next(row for row in resp.json() if row['id'] == user_id)
    assert user['local_traffic'] == {
        'source': 'local_amneziawg',
        'user_id': user_id,
        'rx_bytes': 120,
        'tx_bytes': 80,
        'total_bytes': 200,
        'updated_at': '2026-01-02T03:04:05',
    }


async def test_trigger_sync_enqueues_cleanup_operation(client: AsyncClient, auth_headers, db):
    resp = await client.post('/api/sync', headers=auth_headers)

    assert resp.status_code == HTTPStatus.ACCEPTED
    data = resp.json()
    assert data['operation_id']
    assert data['status_url'] == f'/api/operations/{data["operation_id"]}'

    operations = (await db.execute(select(AsyncOperation))).scalars().all()
    assert {operation.kind for operation in operations} == {
        'sync_all',
        'cleanup_raw_traffic_samples',
    }
    assert {operation.target_type for operation in operations} == {'all', 'traffic'}


async def test_block_user(client: AsyncClient, auth_headers):
    headers = auth_headers
    user_resp = await client.post('/api/users', json={'name': 'block-me'}, headers=headers)
    user_id = user_resp.json()['id']

    resp = await client.put(f'/api/users/{user_id}/block', headers=headers)
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()['is_blocked'] is True


async def test_unblock_user(client: AsyncClient, auth_headers):
    headers = auth_headers
    user_resp = await client.post('/api/users', json={'name': 'unblock-me'}, headers=headers)
    user_id = user_resp.json()['id']

    await client.put(f'/api/users/{user_id}/block', headers=headers)
    resp = await client.put(f'/api/users/{user_id}/unblock', headers=headers)
    assert resp.status_code == HTTPStatus.OK
    assert resp.json()['is_blocked'] is False


async def test_local_unblock_creates_missing_node_peer_without_reviving_deleted_device(
    client: AsyncClient, auth_headers, db
):
    node_a = await client.post(
        '/api/nodes',
        json={'name': 'a', 'url': 'http://agent-a:8000', 'token': 'tok'},
        headers=auth_headers,
    )
    assert node_a.status_code == HTTPStatus.CREATED
    node_a_id = node_a.json()['id']
    user = await client.post('/api/users', json={'name': 'recover'}, headers=auth_headers)
    assert user.status_code == HTTPStatus.CREATED
    user_id = user.json()['id']
    live, _ = await create_device(db, user_id, name='live')
    deleted, _ = await create_device(db, user_id, name='deleted')
    await delete_device(db, deleted)
    await db.commit()
    live_id, deleted_id = live.id, deleted.id

    blocked = await client.put(f'/api/users/{user_id}/block', headers=auth_headers)
    assert blocked.status_code == HTTPStatus.OK
    assert blocked.json()['is_blocked'] is True
    node_b = await client.post(
        '/api/nodes',
        json={'name': 'b', 'url': 'http://agent-b:8000', 'token': 'tok'},
        headers=auth_headers,
    )
    assert node_b.status_code == HTTPStatus.CREATED
    node_b_id = node_b.json()['id']
    peers_b = await client.get(f'/api/nodes/{node_b_id}/peers', headers=auth_headers)
    assert peers_b.status_code == HTTPStatus.OK
    assert peers_b.json() == []

    with patch('app.routers.api.enqueue_sync_node', new=AsyncMock()) as enqueue:
        restored = await client.put(f'/api/users/{user_id}/unblock', headers=auth_headers)
    assert restored.status_code == HTTPStatus.OK
    assert restored.json()['is_blocked'] is False
    assert sorted(call.args[0] for call in enqueue.await_args_list) == sorted(
        [node_a_id, node_b_id]
    )
    db.expire_all()
    peers = (await db.execute(select(Peer).where(Peer.user_id == user_id))).scalars().all()
    assert {(peer.device_id, peer.node_id, peer.status) for peer in peers} == {
        (live_id, node_a_id, 'pending'),
        (live_id, node_b_id, 'pending'),
        (deleted_id, node_a_id, 'pending_delete'),
    }
    tombstone = await db.get(Device, deleted_id)
    assert tombstone.deleted_at is not None
    operation_ids = [call.kwargs['operation_id'] for call in enqueue.await_args_list]
    operations = (
        (await db.execute(select(AsyncOperation).where(AsyncOperation.id.in_(operation_ids))))
        .scalars()
        .all()
    )
    assert {(op.kind, op.target_id, op.status) for op in operations} == {
        ('sync_node', node_a_id, 'queued'),
        ('sync_node', node_b_id, 'queued'),
    }


async def test_block_nonexistent_user(client: AsyncClient, auth_headers):
    headers = auth_headers
    resp = await client.put('/api/users/nonexistent/block', headers=headers)
    assert resp.status_code == HTTPStatus.NOT_FOUND


async def test_delete_user(client: AsyncClient, auth_headers, db):
    """The delete route still keys on the retained legacy columns in this slice.

    A migration-era account has per-user credentials, so it deletes cleanly. A device-only account
    currently cannot pass this guard - device-aware user deletion is next-phase work (see the
    handoff notes), not a change made here.
    """
    headers = auth_headers
    user_resp = await client.post('/api/users', json={'name': 'delete-me'}, headers=headers)
    user_id = user_resp.json()['id']
    user = await db.get(User, user_id)
    user.public_key = 'delete-me-public'
    await db.commit()

    resp = await client.delete(f'/api/users/{user_id}', headers=headers)
    assert resp.status_code == HTTPStatus.NO_CONTENT


async def test_user_local_traffic_requires_auth(client: AsyncClient, auth_headers):
    user_resp = await client.post('/api/users', json={'name': 'local-auth'}, headers=auth_headers)
    user_id = user_resp.json()['id']

    resp = await client.get(f'/api/users/{user_id}/local-traffic')

    assert resp.status_code == HTTPStatus.UNAUTHORIZED


async def test_user_local_traffic_lifetime_zero_for_no_data(client: AsyncClient, auth_headers):
    headers = auth_headers
    user_resp = await client.post('/api/users', json={'name': 'local-empty'}, headers=headers)
    user_id = user_resp.json()['id']

    resp = await client.get(f'/api/users/{user_id}/local-traffic', headers=headers)

    assert resp.status_code == HTTPStatus.OK
    assert resp.json() == {
        'source': 'local_amneziawg',
        'user_id': user_id,
        'rx_bytes': 0,
        'tx_bytes': 0,
        'total_bytes': 0,
        'updated_at': None,
    }


async def test_user_local_traffic_returns_lifetime_daily_and_node_breakdowns(
    client: AsyncClient,
    auth_headers,
    db,
):
    headers = auth_headers
    today = date.today()
    yesterday = today - timedelta(days=1)
    updated_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    node = Node(
        id='node-local-1',
        name='local-node',
        url='http://agent:8000',
        token='tok',  # noqa: S106
    )
    user = User(
        id='user-local-1',
        name='local-usage',
        public_key='user-public',
        private_key='user-private',
        vpn_ip='10.8.0.2',
    )
    peer = Peer(
        id='peer-local-1',
        node_id=node.id,
        user_id=user.id,
        device_id='user-local-1-device',
        status='active',
    )
    db.add_all(
        [
            node,
            user,
            Device(
                id='user-local-1-device',
                user_id=user.id,
                name='Default',
                public_key='user-public',
                private_key='user-private',
                vpn_ip='10.8.0.2',
                is_legacy_default=True,
            ),
            peer,
            LocalAmneziawgUserLifetimeTraffic(
                user_id=user.id,
                rx_bytes=100,
                tx_bytes=250,
                total_bytes=350,
                updated_at=updated_at,
            ),
            LocalAmneziawgUserDailyTraffic(
                user_id=user.id,
                day=today,
                rx_bytes=40,
                tx_bytes=60,
                total_bytes=100,
                updated_at=updated_at,
            ),
            LocalAmneziawgUserDailyTraffic(
                user_id=user.id,
                day=yesterday,
                rx_bytes=60,
                tx_bytes=190,
                total_bytes=250,
                updated_at=updated_at,
            ),
            LocalAmneziawgUserNodeLifetimeTraffic(
                user_id=user.id,
                node_id=node.id,
                rx_bytes=100,
                tx_bytes=250,
                total_bytes=350,
                updated_at=updated_at,
            ),
            LocalAmneziawgUserNodeDailyTraffic(
                user_id=user.id,
                node_id=node.id,
                day=today,
                rx_bytes=40,
                tx_bytes=60,
                total_bytes=100,
                updated_at=updated_at,
            ),
        ]
    )
    await db.commit()

    lifetime_resp = await client.get(f'/api/users/{user.id}/local-traffic', headers=headers)
    daily_resp = await client.get(
        f'/api/users/{user.id}/local-traffic/daily?days=30', headers=headers
    )
    node_resp = await client.get(f'/api/users/{user.id}/local-traffic/nodes', headers=headers)
    node_daily_resp = await client.get(
        f'/api/users/{user.id}/local-traffic/nodes/daily?days=30', headers=headers
    )

    assert lifetime_resp.status_code == HTTPStatus.OK
    assert lifetime_resp.json()['source'] == 'local_amneziawg'
    assert lifetime_resp.json()['rx_bytes'] == 100
    assert lifetime_resp.json()['tx_bytes'] == 250
    assert lifetime_resp.json()['total_bytes'] == 350
    assert daily_resp.status_code == HTTPStatus.OK
    assert [row['day'] for row in daily_resp.json()] == [yesterday.isoformat(), today.isoformat()]
    assert all(row['source'] == 'local_amneziawg' for row in daily_resp.json())
    assert {row['total_bytes'] for row in daily_resp.json()} == {100, 250}
    assert node_resp.status_code == HTTPStatus.OK
    assert node_resp.json()[0]['source'] == 'local_amneziawg'
    assert node_resp.json()[0]['node_id'] == node.id
    assert node_resp.json()[0]['node_name'] == node.name
    assert node_resp.json()[0]['total_bytes'] == 350
    assert node_daily_resp.status_code == HTTPStatus.OK
    assert node_daily_resp.json() == [
        {
            'source': 'local_amneziawg',
            'user_id': user.id,
            'day': today.isoformat(),
            'rx_bytes': 40,
            'tx_bytes': 60,
            'total_bytes': 100,
            'updated_at': '2026-01-02T03:04:05',
            'node_id': node.id,
            'node_name': node.name,
        }
    ]


async def test_node_local_traffic_returns_all_user_totals(client: AsyncClient, auth_headers, db):
    headers = auth_headers
    updated_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    node = Node(
        id='node-total-1',
        name='aggregate-node',
        url='http://agent:8000',
        token='tok',  # noqa: S106
    )
    other_node = Node(
        id='node-total-2',
        name='other-node',
        url='http://agent-2:8000',
        token='tok-2',  # noqa: S106
    )
    first_user = User(id='node-user-1', name='node-user-1')
    second_user = User(id='node-user-2', name='node-user-2')
    db.add_all(
        [
            node,
            other_node,
            first_user,
            second_user,
            LocalAmneziawgUserNodeLifetimeTraffic(
                user_id=first_user.id,
                node_id=node.id,
                rx_bytes=100,
                tx_bytes=250,
                total_bytes=350,
                updated_at=updated_at,
            ),
            LocalAmneziawgUserNodeLifetimeTraffic(
                user_id=second_user.id,
                node_id=node.id,
                rx_bytes=10,
                tx_bytes=20,
                total_bytes=30,
                updated_at=updated_at + timedelta(seconds=1),
            ),
            LocalAmneziawgUserNodeLifetimeTraffic(
                user_id=second_user.id,
                node_id=other_node.id,
                rx_bytes=999,
                tx_bytes=999,
                total_bytes=1998,
                updated_at=updated_at,
            ),
        ]
    )
    await db.commit()

    resp = await client.get(f'/api/nodes/{node.id}/local-traffic', headers=headers)

    assert resp.status_code == HTTPStatus.OK
    assert resp.json() == {
        'source': 'local_amneziawg',
        'node_id': node.id,
        'node_name': node.name,
        'rx_bytes': 110,
        'tx_bytes': 270,
        'total_bytes': 380,
        'updated_at': '2026-01-02T03:04:06',
    }


async def test_node_local_traffic_zero_for_no_data(client: AsyncClient, auth_headers, db):
    node = Node(
        id='node-total-empty',
        name='empty-node',
        url='http://agent:8000',
        token='tok',  # noqa: S106
    )
    db.add(node)
    await db.commit()

    resp = await client.get(f'/api/nodes/{node.id}/local-traffic', headers=auth_headers)

    assert resp.status_code == HTTPStatus.OK
    assert resp.json() == {
        'source': 'local_amneziawg',
        'node_id': node.id,
        'node_name': node.name,
        'rx_bytes': 0,
        'tx_bytes': 0,
        'total_bytes': 0,
        'updated_at': None,
    }


async def test_user_traffic_endpoint_keeps_existing_shape(client: AsyncClient, auth_headers):
    headers = auth_headers
    user_resp = await client.post('/api/users', json={'name': 'legacy-traffic'}, headers=headers)
    user_id = user_resp.json()['id']

    resp = await client.get(f'/api/users/{user_id}/traffic?days=30', headers=headers)

    assert resp.status_code == HTTPStatus.OK
    assert resp.json() == []


# ── Configs ────────────────────────────────────────────────────────────────────


async def test_user_configs_requires_keypair(client: AsyncClient, auth_headers):
    headers = auth_headers
    resp = await client.get('/api/users/nonexistent/configs', headers=headers)
    assert resp.status_code == HTTPStatus.NOT_FOUND


async def test_trigger_sync(client: AsyncClient, auth_headers):
    headers = auth_headers
    resp = await client.post('/api/sync', headers=headers)
    assert resp.status_code == HTTPStatus.ACCEPTED
    data = resp.json()
    assert data['operation_id']
    assert data['status_url'] == f'/api/operations/{data["operation_id"]}'


async def test_get_operation(client: AsyncClient, auth_headers):
    headers = auth_headers
    sync_resp = await client.post('/api/sync', headers=headers)
    operation_id = sync_resp.json()['operation_id']

    resp = await client.get(f'/api/operations/{operation_id}', headers=headers)
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    assert data['id'] == operation_id
    assert data['kind'] == 'sync_all'
    assert data['status'] == 'queued'


# ── User page (public, no auth) ────────────────────────────────────────────────


async def test_pub_user_info_not_found(client: AsyncClient):
    resp = await client.get('/pub/u/nonexistent/info')
    assert resp.status_code == HTTPStatus.NOT_FOUND


async def test_pub_user_info_blocked(client: AsyncClient, auth_headers):
    headers = auth_headers
    user_resp = await client.post('/api/users', json={'name': 'blocked-user'}, headers=headers)
    user_id = user_resp.json()['id']
    await client.put(f'/api/users/{user_id}/block', headers=headers)

    resp = await client.get(f'/pub/u/{user_id}/info')
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    assert data['blocked'] is True
    assert data['status'] == {'code': 'blocked', 'reason': 'blocked'}
    assert data['subscription'] == {
        'managed': False,
        'expire_at': None,
        'last_synced_at': None,
    }
    assert data['traffic'] == {
        'used_bytes': 0,
        'limit_bytes': None,
        'local_used_bytes': 0,
        'remote_used_bytes': 0,
        'updated_at': None,
    }
    assert data['updated_at'] is None


async def test_pub_user_info_active(client: AsyncClient, auth_headers, db):
    headers = auth_headers
    user_resp = await client.post('/api/users', json={'name': 'active-user'}, headers=headers)
    user_id = user_resp.json()['id']
    updated_at = datetime(2026, 1, 2, 3, 4, 6)
    db.add(
        LocalAmneziawgUserLifetimeTraffic(
            user_id=user_id,
            rx_bytes=120,
            tx_bytes=340,
            total_bytes=460,
            updated_at=updated_at,
        )
    )
    await db.commit()

    resp = await client.get(f'/pub/u/{user_id}/info')
    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    assert data['blocked'] is False
    assert data['user_name'] == 'active-user'
    assert data['status'] == {'code': 'active', 'reason': None}
    assert data['subscription'] == {
        'managed': False,
        'expire_at': None,
        'last_synced_at': None,
    }
    assert data['traffic'] == {
        'used_bytes': 460,
        'limit_bytes': None,
        'local_used_bytes': 460,
        'remote_used_bytes': 0,
        'updated_at': '2026-01-02T03:04:06',
    }
    assert data['updated_at'] == '2026-01-02T03:04:06'


async def test_pub_user_info_remnawave_uses_readable_display_name(
    client: AsyncClient, auth_headers, db
) -> None:
    headers = auth_headers
    user_resp = await client.post('/api/users', json={'name': 'rw-user-1'}, headers=headers)
    user_id = user_resp.json()['id']
    db.add(
        RemnawaveUser(
            user_id=user_id,
            remnawave_uuid='rw-user-1-uuid',
            username='rw_user_1',
            status='ACTIVE',
            description='Bot user: Любовь',
            telegram_id=111222333,
        )
    )
    await db.commit()

    resp = await client.get(f'/pub/u/{user_id}/info')

    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    assert data['user_name'] == 'Любовь'
    assert data['subscription']['managed'] is True
    assert 'remnawave' not in data
    assert 'telegram_url' not in data
    assert 'subscription_url' not in data


@pytest.mark.parametrize(
    'description',
    [None, 'not a bot description', 'Bot user: @handle_only'],
)
async def test_pub_user_info_remnawave_falls_back_to_user_name_without_display_name(
    client: AsyncClient, auth_headers, db, description: str | None
) -> None:
    headers = auth_headers
    user_resp = await client.post('/api/users', json={'name': 'rw-fallback-user'}, headers=headers)
    user_id = user_resp.json()['id']
    db.add(
        RemnawaveUser(
            user_id=user_id,
            remnawave_uuid=f'rw-fallback-{description!r}',
            username='rw_fallback_user',
            status='ACTIVE',
            description=description,
            telegram_id=444555666,
            subscription_url_encrypted='encrypted-remnawave-link',
        )
    )
    await db.commit()

    resp = await client.get(f'/pub/u/{user_id}/info')

    assert resp.status_code == HTTPStatus.OK
    data = resp.json()
    assert data['user_name'] == 'rw-fallback-user'
    assert data['subscription']['managed'] is True
    assert 'remnawave' not in data
    assert 'telegram_url' not in data
    assert 'subscription_url' not in data


async def test_pub_qr_not_found(client: AsyncClient):
    resp = await client.get('/pub/u/nonexistent/qr/awg/nonexistent')
    assert resp.status_code == HTTPStatus.NOT_FOUND
