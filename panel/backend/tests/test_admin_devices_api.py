"""Admin device API: per-user device limit, device listing, device-aware configs/QR/ZIP.

Every test drives the real HTTP surface (``/api/...``) against the database, so the admin contract -
the local device limit, the non-secret device view, the readiness gates on downloads and the archive
layout - is exercised end to end instead of through service calls.

The refused cases are as important as the served ones: a pending peer, a tombstoned device, a
blocked account and a user without a migration ``Default`` device must all fail *informatively* and
never fall back to another device or to the retained per-user credential columns.
"""

from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime
from http import HTTPStatus

from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AsyncOperation, Device, Node, Peer, RemnawaveUser, User
from app.routers.api_parts.common import REMNAWAVE_MANAGED_USER_CONFLICT_DETAIL
from app.routers.api_parts.configs import NOTHING_READY_DETAIL

NODE_METADATA = {'server_public_key': 'node-public', 'server_endpoint': 'vpn.example:51820'}


# ── seeding ────────────────────────────────────────────────────────────────────


async def _seed_node(
    db: AsyncSession, node_id: str = 'node-1', name: str | None = None, **overrides
) -> Node:
    data: dict = {
        'id': node_id,
        'name': name if name is not None else node_id,
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


async def _seed_remnawave_user(
    db: AsyncSession, *, name: str = 'remna', hwid_device_limit: int | None = 0, **overrides
) -> User:
    user = User(id=f'user-{name}', name=name)
    db.add(user)
    await db.flush()
    db.add(
        RemnawaveUser(
            user_id=user.id,
            remnawave_uuid=f'uuid-{name}',
            username=name,
            status='ACTIVE',
            hwid_device_limit=hwid_device_limit,
            **overrides,
        )
    )
    await db.commit()
    return user


async def _seed_device(db: AsyncSession, user: User, device_id: str, **overrides) -> Device:
    data: dict = {
        'id': device_id,
        'user_id': user.id,
        'name': 'laptop',
        'public_key': f'{device_id}-public',
        'private_key': f'{device_id}-private',
        'vpn_ip': '10.8.0.2',
        'is_legacy_default': False,
        'deleted_at': None,
    }
    data.update(overrides)
    device = Device(**data)
    db.add(device)
    await db.commit()
    return device


async def _seed_peer(
    db: AsyncSession,
    *,
    node: Node,
    device: Device,
    status: str = 'active',
    psk_key: str | None = None,
) -> Peer:
    peer = Peer(
        id=f'peer-{node.id}-{device.id}',
        node_id=node.id,
        user_id=device.user_id,
        device_id=device.id,
        status=status,
        psk_key=psk_key if psk_key is not None else f'{device.id}-psk',
    )
    db.add(peer)
    await db.commit()
    return peer


def _zip_names(payload: bytes) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = archive.namelist()
        assert archive.testzip() is None
    return names


def _zip_text(payload: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        return '\n'.join(archive.read(name).decode() for name in archive.namelist())


async def _count(db: AsyncSession, model, *criteria) -> int:
    statement = select(func.count()).select_from(model)
    if criteria:
        statement = statement.where(*criteria)
    return int(await db.scalar(statement) or 0)


# ── authentication ─────────────────────────────────────────────────────────────


async def test_admin_device_surfaces_require_auth(client: AsyncClient, db, auth_headers) -> None:
    user = await _seed_user(db, name='auth')

    assert (await client.get('/api/users')).status_code == HTTPStatus.UNAUTHORIZED
    assert (await client.get(f'/api/users/{user.id}/devices')).status_code == (
        HTTPStatus.UNAUTHORIZED
    )
    assert (await client.get(f'/api/users/{user.id}/configs')).status_code == (
        HTTPStatus.UNAUTHORIZED
    )
    assert (await client.get(f'/api/users/{user.id}/configs/zip')).status_code == (
        HTTPStatus.UNAUTHORIZED
    )
    assert (
        await client.put(f'/api/users/{user.id}/device-limit', json={'device_limit': 1})
    ).status_code == HTTPStatus.UNAUTHORIZED
    assert auth_headers['Authorization'].startswith('Bearer ')


# ── creating a local account ───────────────────────────────────────────────────


async def test_new_local_user_has_zero_limit_and_no_devices(
    client: AsyncClient, db, auth_headers
) -> None:
    created = await client.post('/api/users', json={'name': 'fresh'}, headers=auth_headers)

    assert created.status_code == HTTPStatus.CREATED
    body = created.json()
    assert body['device_limit'] == 0
    assert body['public_key'] is None

    devices = await client.get(f'/api/users/{body["id"]}/devices', headers=auth_headers)
    assert devices.status_code == HTTPStatus.OK
    assert devices.json() == {
        'user_id': body['id'],
        'device_limit': 0,
        'effective_device_limit': 0,
        'device_count': 0,
        'devices': [],
    }

    # Nothing is provisioned implicitly: no device, key, peer or queued node work.
    assert await _count(db, Device, Device.user_id == body['id']) == 0
    assert await _count(db, Peer, Peer.user_id == body['id']) == 0
    assert await _count(db, AsyncOperation) == 0
    user = await db.get(User, body['id'])
    assert (user.private_key, user.vpn_ip) == (None, None)


async def test_new_local_user_accepts_initial_device_limit(
    client: AsyncClient, db, auth_headers
) -> None:
    created = await client.post(
        '/api/users', json={'name': 'limited', 'device_limit': 3}, headers=auth_headers
    )

    assert created.status_code == HTTPStatus.CREATED
    assert created.json()['device_limit'] == 3
    assert await _count(db, Device, Device.user_id == created.json()['id']) == 0

    devices = await client.get(f'/api/users/{created.json()["id"]}/devices', headers=auth_headers)
    assert devices.json()['effective_device_limit'] == 3
    assert devices.json()['device_count'] == 0


# ── the local device limit ─────────────────────────────────────────────────────


async def test_device_limit_update_stores_positive_and_unlimited(
    client: AsyncClient, db, auth_headers
) -> None:
    user = await _seed_user(db, name='limit')

    raised = await client.put(
        f'/api/users/{user.id}/device-limit', json={'device_limit': 4}, headers=auth_headers
    )
    assert raised.status_code == HTTPStatus.OK
    assert raised.json()['device_limit'] == 4
    assert raised.json()['effective_device_limit'] == 4

    cleared = await client.put(
        f'/api/users/{user.id}/device-limit', json={'device_limit': 0}, headers=auth_headers
    )
    assert cleared.status_code == HTTPStatus.OK
    assert cleared.json()['device_limit'] == 0
    # 0 means unlimited, and unlimited is reported as 0.
    assert cleared.json()['effective_device_limit'] == 0

    await db.refresh(user)
    assert user.device_limit == 0


async def test_device_limit_update_rejects_negative_and_missing_user(
    client: AsyncClient, db, auth_headers
) -> None:
    user = await _seed_user(db, name='negative')

    rejected = await client.put(
        f'/api/users/{user.id}/device-limit', json={'device_limit': -1}, headers=auth_headers
    )
    assert rejected.status_code == HTTPStatus.UNPROCESSABLE_ENTITY

    await db.refresh(user)
    assert user.device_limit == 0

    missing = await client.put(
        '/api/users/nonexistent/device-limit', json={'device_limit': 1}, headers=auth_headers
    )
    assert missing.status_code == HTTPStatus.NOT_FOUND


async def test_device_limit_update_refuses_remnawave_managed_user(
    client: AsyncClient, db, auth_headers
) -> None:
    user = await _seed_remnawave_user(db, name='managed', hwid_device_limit=2)

    refused = await client.put(
        f'/api/users/{user.id}/device-limit', json={'device_limit': 9}, headers=auth_headers
    )

    assert refused.status_code == HTTPStatus.CONFLICT
    assert refused.json()['detail'] == REMNAWAVE_MANAGED_USER_CONFLICT_DETAIL
    await db.refresh(user)
    assert user.device_limit == 0

    # The effective limit stays the imported one, and the brief reports it.
    devices = await client.get(f'/api/users/{user.id}/devices', headers=auth_headers)
    assert devices.json()['device_limit'] == 0
    assert devices.json()['effective_device_limit'] == 2

    listed = (await client.get('/api/users', headers=auth_headers)).json()
    row = next(item for item in listed if item['id'] == user.id)
    assert row['remnawave']['hwid_device_limit'] == 2
    assert row['effective_device_limit'] == 2


async def test_imported_null_hwid_limit_is_unlimited_not_the_local_column(
    client: AsyncClient, db, auth_headers
) -> None:
    """A Remnawave owner with an imported ``null`` limit is unlimited on every read surface.

    The local per-user column must not leak back into the answer: it is inert for an imported
    profile, so reporting it would silently cap an account Remnawave marked unlimited. The column
    itself stays readable - the admin still sees what is stored - but it never decides.
    """
    user = await _seed_remnawave_user(db, name='imported-null', hwid_device_limit=None)
    user.device_limit = 1
    await db.commit()

    devices = await client.get(f'/api/users/{user.id}/devices', headers=auth_headers)
    assert devices.json()['device_limit'] == 1
    assert devices.json()['effective_device_limit'] == 0

    listed = (await client.get('/api/users', headers=auth_headers)).json()
    row = next(item for item in listed if item['id'] == user.id)
    assert row['effective_device_limit'] == 0


async def test_lowering_device_limit_keeps_existing_devices(
    client: AsyncClient, db, auth_headers
) -> None:
    user = await _seed_user(db, name='lower')
    await _seed_device(db, user, device_id='device-a', vpn_ip='10.8.0.2')
    await _seed_device(db, user, device_id='device-b', vpn_ip='10.8.0.3')

    lowered = await client.put(
        f'/api/users/{user.id}/device-limit', json={'device_limit': 1}, headers=auth_headers
    )

    assert lowered.status_code == HTTPStatus.OK
    body = lowered.json()
    assert body['effective_device_limit'] == 1
    assert body['device_count'] == 2
    assert {device['id'] for device in body['devices']} == {'device-a', 'device-b'}
    assert await _count(db, Device, Device.user_id == user.id) == 2


# ── device listing ─────────────────────────────────────────────────────────────


async def test_device_listing_is_non_secret_and_reports_per_node_availability(
    client: AsyncClient, db, auth_headers
) -> None:
    node = await _seed_node(db, 'node-1', **NODE_METADATA)
    bare_node = await _seed_node(db, 'node-2')
    user = await _seed_user(db, name='view')
    device = await _seed_device(db, user, device_id='device-a', name='laptop')
    await _seed_peer(db, node=node, device=device, status='active')
    await _seed_peer(db, node=bare_node, device=device, status='pending')

    listed = await client.get(f'/api/users/{user.id}/devices', headers=auth_headers)

    assert listed.status_code == HTTPStatus.OK
    body = listed.json()
    assert body['device_count'] == 1
    [entry] = body['devices']
    assert entry['id'] == 'device-a'
    assert entry['name'] == 'laptop'
    assert entry['vpn_ip'] == '10.8.0.2'
    assert entry['status'] == 'ready'
    assert {node_entry['node_id']: node_entry['status'] for node_entry in entry['nodes']} == {
        'node-1': 'ready',
        'node-2': 'pending',
    }
    assert {node_entry['node_id']: node_entry['ready'] for node_entry in entry['nodes']} == {
        'node-1': True,
        'node-2': False,
    }
    # No key material anywhere in the device view.
    serialized = listed.text
    assert 'device-a-private' not in serialized
    assert 'device-a-public' not in serialized


async def test_user_list_exposes_device_limit_count_and_devices(
    client: AsyncClient, db, auth_headers
) -> None:
    node = await _seed_node(db, 'node-1', **NODE_METADATA)
    user = await _seed_user(db, name='listed', device_limit=2)
    await _seed_device(db, user, device_id='device-a', name='laptop')
    device = await _seed_device(db, user, device_id='device-b', name='phone', vpn_ip='10.8.0.3')
    await _seed_peer(db, node=node, device=device, status='active')
    await _seed_remnawave_user(db, name='imported', hwid_device_limit=7)

    listed = (await client.get('/api/users', headers=auth_headers)).json()
    local = next(item for item in listed if item['id'] == user.id)
    assert local['device_limit'] == 2
    assert local['effective_device_limit'] == 2
    assert local['device_count'] == 2
    assert {entry['name'] for entry in local['devices']} == {'laptop', 'phone'}

    imported = next(item for item in listed if item['name'] == 'imported')
    assert imported['device_limit'] == 0
    assert imported['effective_device_limit'] == 7
    assert imported['remnawave']['hwid_device_limit'] == 7


async def test_node_peer_list_carries_per_device_identity(
    client: AsyncClient, db, auth_headers
) -> None:
    node = await _seed_node(db, 'node-1', **NODE_METADATA)
    user = await _seed_user(db, name='peers')
    first = await _seed_device(db, user, device_id='device-a', name='laptop', vpn_ip='10.8.0.2')
    second = await _seed_device(db, user, device_id='device-b', name='phone', vpn_ip='10.8.0.3')
    await _seed_peer(db, node=node, device=first, status='active')
    await _seed_peer(db, node=node, device=second, status='pending')

    peers = (await client.get(f'/api/nodes/{node.id}/peers', headers=auth_headers)).json()

    assert len(peers) == 2
    assert len({peer['id'] for peer in peers}) == 2
    by_device = {peer['device_id']: peer for peer in peers}
    assert set(by_device) == {'device-a', 'device-b'}
    assert by_device['device-a']['device_name'] == 'laptop'
    assert by_device['device-a']['vpn_ip'] == '10.8.0.2'
    assert by_device['device-b']['device_name'] == 'phone'
    assert by_device['device-b']['vpn_ip'] == '10.8.0.3'

    listed = (await client.get('/api/users', headers=auth_headers)).json()
    row = next(item for item in listed if item['id'] == user.id)
    briefs = {brief['device_id']: brief for brief in row['peers']}
    assert set(briefs) == {'device-a', 'device-b'}
    assert len({brief['id'] for brief in briefs.values()}) == 2
    assert briefs['device-b']['device_name'] == 'phone'
    assert briefs['device-b']['vpn_ip'] == '10.8.0.3'


# ── device-scoped configuration downloads ─────────────────────────────────────


async def test_two_devices_on_one_node_serve_their_own_credentials(
    client: AsyncClient, db, auth_headers
) -> None:
    node = await _seed_node(db, 'node-1', **NODE_METADATA)
    user = await _seed_user(db, name='twodevices')
    first = await _seed_device(
        db, user, device_id='device-a', private_key='key-a', vpn_ip='10.8.0.2'
    )
    second = await _seed_device(
        db, user, device_id='device-b', private_key='key-b', vpn_ip='10.8.0.3'
    )
    await _seed_peer(db, node=node, device=first, psk_key='psk-a')
    await _seed_peer(db, node=node, device=second, psk_key='psk-b')

    config = await client.get(
        f'/api/users/{user.id}/devices/device-a/configs/{node.id}', headers=auth_headers
    )

    assert config.status_code == HTTPStatus.OK
    assert 'PrivateKey = key-a' in config.text
    assert 'Address = 10.8.0.2/32' in config.text
    assert 'PresharedKey = psk-a' in config.text
    assert 'key-b' not in config.text
    assert 'psk-b' not in config.text
    assert config.headers['content-disposition'].startswith('attachment; filename=')

    other = await client.get(
        f'/api/users/{user.id}/devices/device-b/configs/{node.id}', headers=auth_headers
    )
    assert other.status_code == HTTPStatus.OK
    assert 'PrivateKey = key-b' in other.text
    assert 'PresharedKey = psk-b' in other.text
    assert 'key-a' not in other.text

    for suffix in ('qr', 'qr-amnezia'):
        response = await client.get(
            f'/api/users/{user.id}/devices/device-a/{suffix}/{node.id}', headers=auth_headers
        )
        assert response.status_code == HTTPStatus.OK
        assert response.headers['content-type'].startswith('image/svg+xml')

    entries = await client.get(
        f'/api/users/{user.id}/devices/device-a/configs', headers=auth_headers
    )
    assert entries.status_code == HTTPStatus.OK
    assert entries.json() == [
        {'node_id': node.id, 'node_name': node.name, 'config': entries.json()[0]['config']}
    ]
    assert 'PrivateKey = key-a' in entries.json()[0]['config']


async def test_device_scoped_zip_contains_only_that_device(
    client: AsyncClient, db, auth_headers
) -> None:
    # Two nodes deliberately share a display name: within one device's archive that collides, and
    # the archive must still be valid and address every entry.
    first_node = await _seed_node(db, 'node-1', 'shared', **NODE_METADATA)
    second_node = await _seed_node(db, 'node-2', 'shared', **NODE_METADATA)
    user = await _seed_user(db, name='devzip')
    first = await _seed_device(
        db, user, device_id='device-a', private_key='key-a', vpn_ip='10.8.0.2'
    )
    second = await _seed_device(
        db, user, device_id='device-b', private_key='key-b', vpn_ip='10.8.0.3'
    )
    for node in (first_node, second_node):
        await _seed_peer(db, node=node, device=first, psk_key='psk-a')
        await _seed_peer(db, node=node, device=second, psk_key='psk-b')

    response = await client.get(
        f'/api/users/{user.id}/devices/device-a/configs/zip', headers=auth_headers
    )

    assert response.status_code == HTTPStatus.OK
    assert response.headers['content-type'] == 'application/zip'
    names = _zip_names(response.content)
    assert len(names) == 2
    assert len(set(names)) == 2
    text = _zip_text(response.content)
    assert text.count('PrivateKey = key-a') == 2
    assert 'key-b' not in text


async def test_user_wide_zip_covers_every_live_device_with_unique_entries(
    client: AsyncClient, db, auth_headers
) -> None:
    first_node = await _seed_node(db, 'node-1', 'shared', **NODE_METADATA)
    second_node = await _seed_node(db, 'node-2', 'shared', **NODE_METADATA)
    user = await _seed_user(db, name='userzip')
    # Identical device names: the archive has to stay unambiguous on the device identifier alone.
    first = await _seed_device(
        db, user, device_id='device-a', name='laptop', private_key='key-a', vpn_ip='10.8.0.2'
    )
    second = await _seed_device(
        db, user, device_id='device-b', name='laptop', private_key='key-b', vpn_ip='10.8.0.3'
    )
    for node in (first_node, second_node):
        await _seed_peer(db, node=node, device=first, psk_key='psk-a')
        await _seed_peer(db, node=node, device=second, psk_key='psk-b')

    response = await client.get(f'/api/users/{user.id}/configs/zip', headers=auth_headers)

    assert response.status_code == HTTPStatus.OK
    names = _zip_names(response.content)
    assert len(names) == 4
    assert len(set(names)) == 4
    folders = {name.split('/')[0] for name in names}
    assert len(folders) == 2
    assert any('device-a' in folder for folder in folders)
    assert any('device-b' in folder for folder in folders)
    text = _zip_text(response.content)
    assert text.count('PrivateKey = key-a') == 2
    assert text.count('PrivateKey = key-b') == 2


async def test_zip_only_contains_ready_entries_and_refuses_when_nothing_is_ready(
    client: AsyncClient, db, auth_headers
) -> None:
    ready_node = await _seed_node(db, 'node-1', **NODE_METADATA)
    pending_node = await _seed_node(db, 'node-2', **NODE_METADATA)
    user = await _seed_user(db, name='partial')
    device = await _seed_device(db, user, device_id='device-a', private_key='key-a')
    await _seed_peer(db, node=ready_node, device=device, status='active')
    await _seed_peer(db, node=pending_node, device=device, status='pending')

    response = await client.get(
        f'/api/users/{user.id}/devices/device-a/configs/zip', headers=auth_headers
    )
    assert response.status_code == HTTPStatus.OK
    assert len(_zip_names(response.content)) == 1

    waiting = await _seed_user(db, name='waiting')
    waiting_device = await _seed_device(db, waiting, device_id='device-w', vpn_ip='10.8.0.7')
    await _seed_peer(db, node=pending_node, device=waiting_device, status='pending')
    refused = await client.get(
        f'/api/users/{waiting.id}/devices/device-w/configs/zip', headers=auth_headers
    )
    assert refused.status_code == HTTPStatus.CONFLICT
    assert refused.json()['detail'] == NOTHING_READY_DETAIL

    # A user with no live device at all gets the same diagnosable refusal from the user archive.
    empty = await _seed_user(db, name='nodevices')
    nothing = await client.get(f'/api/users/{empty.id}/configs/zip', headers=auth_headers)
    assert nothing.status_code == HTTPStatus.CONFLICT


# ── readiness and account-state safeguards ────────────────────────────────────


async def test_pending_peer_blocks_device_config_downloads(
    client: AsyncClient, db, auth_headers
) -> None:
    node = await _seed_node(db, 'node-1', **NODE_METADATA)
    user = await _seed_user(db, name='pending')
    device = await _seed_device(db, user, device_id='device-a')
    await _seed_peer(db, node=node, device=device, status='pending')
    base = f'/api/users/{user.id}/devices/device-a'

    for path in (
        f'{base}/configs/{node.id}',
        f'{base}/qr/{node.id}',
        f'{base}/qr-amnezia/{node.id}',
    ):
        response = await client.get(path, headers=auth_headers)
        assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE

    # The listing still reports the node as pending instead of hiding it.
    entries = await client.get(f'{base}/configs', headers=auth_headers)
    assert entries.status_code == HTTPStatus.OK
    assert entries.json()[0]['config'] is None


async def test_node_metadata_missing_blocks_config_downloads(
    client: AsyncClient, db, auth_headers
) -> None:
    node = await _seed_node(db, 'node-1')
    user = await _seed_user(db, name='nometa')
    device = await _seed_device(db, user, device_id='device-a')
    await _seed_peer(db, node=node, device=device, status='active')

    response = await client.get(
        f'/api/users/{user.id}/devices/device-a/configs/{node.id}', headers=auth_headers
    )

    assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE


async def test_blocked_account_cannot_download_but_stays_visible(
    client: AsyncClient, db, auth_headers
) -> None:
    node = await _seed_node(db, 'node-1', **NODE_METADATA)
    user = await _seed_user(db, name='blocked', is_blocked=True)
    device = await _seed_device(db, user, device_id='device-a')
    await _seed_peer(db, node=node, device=device, status='active')
    base = f'/api/users/{user.id}/devices/device-a'

    for path in (
        f'{base}/configs',
        f'{base}/configs/zip',
        f'{base}/configs/{node.id}',
        f'{base}/qr/{node.id}',
        f'{base}/qr-amnezia/{node.id}',
        f'/api/users/{user.id}/configs/zip',
    ):
        response = await client.get(path, headers=auth_headers)
        assert response.status_code == HTTPStatus.FORBIDDEN

    visible = await client.get(f'/api/users/{user.id}/devices', headers=auth_headers)
    assert visible.status_code == HTTPStatus.OK
    assert visible.json()['device_count'] == 1


async def test_unknown_and_foreign_devices_are_not_found(
    client: AsyncClient, db, auth_headers
) -> None:
    node = await _seed_node(db, 'node-1', **NODE_METADATA)
    owner = await _seed_user(db, name='owner')
    stranger = await _seed_user(db, name='stranger')
    device = await _seed_device(db, owner, device_id='device-a')
    await _seed_peer(db, node=node, device=device, status='active')

    assert (
        await client.get(f'/api/users/{owner.id}/devices/nope/configs', headers=auth_headers)
    ).status_code == HTTPStatus.NOT_FOUND
    assert (
        await client.get(f'/api/users/{stranger.id}/devices/device-a/configs', headers=auth_headers)
    ).status_code == HTTPStatus.NOT_FOUND
    assert (
        await client.get(
            f'/api/users/{owner.id}/devices/device-a/configs/node-unknown', headers=auth_headers
        )
    ).status_code == HTTPStatus.NOT_FOUND
    assert (
        await client.get('/api/users/user-unknown/devices', headers=auth_headers)
    ).status_code == HTTPStatus.NOT_FOUND


async def test_tombstoned_device_is_not_found(client: AsyncClient, db, auth_headers) -> None:
    node = await _seed_node(db, 'node-1', **NODE_METADATA)
    user = await _seed_user(db, name='deleted')
    device = await _seed_device(
        db, user, device_id='device-a', deleted_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    await _seed_peer(db, node=node, device=device, status='pending_delete')

    response = await client.get(
        f'/api/users/{user.id}/devices/device-a/configs/{node.id}', headers=auth_headers
    )

    assert response.status_code == HTTPStatus.NOT_FOUND
    listed = await client.get(f'/api/users/{user.id}/devices', headers=auth_headers)
    assert listed.json()['device_count'] == 0
    assert listed.json()['devices'] == []


# ── legacy implicit routes: migration Default device only ─────────────────────


async def test_legacy_config_routes_serve_the_migration_default_device(
    client: AsyncClient, db, auth_headers
) -> None:
    node = await _seed_node(db, 'node-1', **NODE_METADATA)
    user = await _seed_user(db, name='legacy')
    device = await _seed_device(
        db,
        user,
        device_id='device-default',
        name='Default',
        private_key='legacy-key',
        vpn_ip='10.8.0.2',
        is_legacy_default=True,
    )
    await _seed_peer(db, node=node, device=device, status='active', psk_key='legacy-psk')

    config = await client.get(f'/api/users/{user.id}/configs/{node.id}', headers=auth_headers)
    assert config.status_code == HTTPStatus.OK
    assert 'PrivateKey = legacy-key' in config.text
    assert 'PresharedKey = legacy-psk' in config.text

    for suffix in ('qr', 'qr-amnezia'):
        qr = await client.get(f'/api/users/{user.id}/{suffix}/{node.id}', headers=auth_headers)
        assert qr.status_code == HTTPStatus.OK

    entries = await client.get(f'/api/users/{user.id}/configs', headers=auth_headers)
    assert entries.status_code == HTTPStatus.OK
    assert 'PrivateKey = legacy-key' in entries.json()[0]['config']

    archive = await client.get(f'/api/users/{user.id}/configs/zip', headers=auth_headers)
    assert archive.status_code == HTTPStatus.OK
    assert 'PrivateKey = legacy-key' in _zip_text(archive.content)


async def test_legacy_config_routes_never_substitute_another_device(
    client: AsyncClient, db, auth_headers
) -> None:
    node = await _seed_node(db, 'node-1', **NODE_METADATA)
    user = await _seed_user(db, name='nodefault')
    device = await _seed_device(db, user, device_id='device-a', private_key='key-a')
    await _seed_peer(db, node=node, device=device, status='active', psk_key='psk-a')

    # The device-specific implicit routes need the migration device and refuse instead of picking
    # the only other device the user happens to own.
    for path in (
        f'/api/users/{user.id}/configs',
        f'/api/users/{user.id}/configs/{node.id}',
        f'/api/users/{user.id}/qr/{node.id}',
        f'/api/users/{user.id}/qr-amnezia/{node.id}',
    ):
        response = await client.get(path, headers=auth_headers)
        assert response.status_code == HTTPStatus.CONFLICT, path
        assert 'device' in response.json()['detail'].lower(), path

    # The archive is user-wide by contract, so it covers this device without needing a Default.
    archive = await client.get(f'/api/users/{user.id}/configs/zip', headers=auth_headers)
    assert archive.status_code == HTTPStatus.OK
    assert 'PrivateKey = key-a' in _zip_text(archive.content)

    # The device itself stays reachable through the explicit route.
    explicit = await client.get(
        f'/api/users/{user.id}/devices/device-a/configs/{node.id}', headers=auth_headers
    )
    assert explicit.status_code == HTTPStatus.OK


async def test_legacy_config_routes_refuse_a_tombstoned_default_device(
    client: AsyncClient, db, auth_headers
) -> None:
    node = await _seed_node(db, 'node-1', **NODE_METADATA)
    user = await _seed_user(db, name='deaddefault')
    await _seed_device(
        db,
        user,
        device_id='device-default',
        name='Default',
        is_legacy_default=True,
        deleted_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    response = await client.get(f'/api/users/{user.id}/configs/{node.id}', headers=auth_headers)

    assert response.status_code == HTTPStatus.CONFLICT


# ── deletion ───────────────────────────────────────────────────────────────────


async def test_deleting_a_device_only_account_cleans_every_peer_and_syncs_nodes(
    client: AsyncClient, db, auth_headers
) -> None:
    first_node = await _seed_node(db, 'node-1', **NODE_METADATA)
    second_node = await _seed_node(db, 'node-2', **NODE_METADATA)
    created = await client.post('/api/users', json={'name': 'delete-me'}, headers=auth_headers)
    user_id = created.json()['id']
    user = await db.get(User, user_id)
    first = await _seed_device(db, user, device_id='device-a', vpn_ip='10.8.0.2')
    second = await _seed_device(db, user, device_id='device-b', vpn_ip='10.8.0.3')
    for node in (first_node, second_node):
        await _seed_peer(db, node=node, device=first)
        await _seed_peer(db, node=node, device=second)

    # A device-oriented account has no legacy key material at all, and deleting it still works.
    assert user.public_key is None
    response = await client.delete(f'/api/users/{user_id}', headers=auth_headers)

    assert response.status_code == HTTPStatus.NO_CONTENT
    assert await _count(db, Device, Device.user_id == user_id) == 0
    assert await _count(db, Peer, Peer.user_id == user_id) == 0

    operations = (
        (await db.execute(select(AsyncOperation).where(AsyncOperation.kind == 'sync_node')))
        .scalars()
        .all()
    )
    assert {operation.target_id for operation in operations} == {'node-1', 'node-2'}
