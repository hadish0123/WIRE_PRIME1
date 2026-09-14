"""Device ownership services: creation, limits, IP allocation, deletion and pending peers."""

import asyncio
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.crypto import allocate_ip as crypto_allocate_ip
from app.models import (
    Device,
    LocalAmneziawgUserLifetimeTraffic,
    Node as NodeModel,
    Peer,
    RemnawaveUser,
    User,
)
from app.services.account_policy import AccountInactiveError, fresh_account_status
from app.services.devices import (
    DeviceIpAllocationError,
    DeviceIpPoolExhaustedError,
    DeviceLimitExceededError,
    count_live_devices,
    create_device,
    create_pending_peer,
    create_pending_peers_for_device,
    create_pending_peers_for_node,
    delete_device,
    effective_device_limit,
    get_legacy_default_device,
    list_live_devices,
    release_device_ips,
)
from app.services.users import create_local_user


async def _device_ips(db: AsyncSession) -> set[str]:
    return {
        ip
        for ip in (
            await db.execute(select(Device.vpn_ip).where(Device.vpn_ip.isnot(None)))
        ).scalars()
        if ip
    }


async def _clear_node_peers(db: AsyncSession, node_id: str) -> None:
    await db.execute(delete(Peer).where(Peer.node_id == node_id))
    await db.commit()


async def _make_node(db: AsyncSession, node_id: str = 'node-1') -> NodeModel:
    node = NodeModel(
        id=node_id,
        name=node_id,
        url=f'http://{node_id}:8000',
        token='tok',  # noqa: S106
    )
    db.add(node)
    await db.commit()
    return node


async def _make_user(db: AsyncSession, user_id: str = 'user-1', name: str = 'alice') -> User:
    user = User(id=user_id, name=name)
    db.add(user)
    await db.commit()
    return user


async def test_new_local_user_has_no_keys_devices_or_peers(db: AsyncSession) -> None:
    await _make_node(db)

    user = await create_local_user(db, 'alice')
    await db.commit()

    assert user.public_key is None
    assert user.private_key is None
    assert user.vpn_ip is None
    assert (await db.execute(select(Device).where(Device.user_id == user.id))).scalars().all() == []
    assert (await db.execute(select(Peer).where(Peer.user_id == user.id))).scalars().all() == []


async def test_create_device_allocates_its_own_credentials_and_pending_peers(
    db: AsyncSession,
) -> None:
    await _make_node(db, 'node-1')
    await _make_node(db, 'node-2')
    user = await create_local_user(db, 'alice')

    device, node_ids = await create_device(db, user.id, name='laptop')
    await db.commit()

    assert device.public_key and device.private_key and device.vpn_ip
    assert device.deleted_at is None
    assert device.is_legacy_default is False
    assert node_ids == {'node-1', 'node-2'}
    # the operational core never writes the retained legacy user columns
    assert user.public_key is None
    assert user.vpn_ip is None

    peers = (
        (await db.execute(select(Peer).where(Peer.device_id == device.id).order_by(Peer.node_id)))
        .scalars()
        .all()
    )
    assert [peer.node_id for peer in peers] == ['node-1', 'node-2']
    assert {peer.status for peer in peers} == {'pending'}
    assert {peer.user_id for peer in peers} == {user.id}
    assert len({peer.psk_key for peer in peers}) == 2


async def test_two_devices_of_same_owner_get_separate_keys_ips_and_peers(
    db: AsyncSession,
) -> None:
    await _make_node(db)
    user = await _make_user(db)

    first, _ = await create_device(db, user.id, name='laptop')
    second, _ = await create_device(db, user.id, name='phone')
    await db.commit()

    assert first.public_key != second.public_key
    assert first.private_key != second.private_key
    assert first.vpn_ip != second.vpn_ip

    peers = (await db.execute(select(Peer).where(Peer.node_id == 'node-1'))).scalars().all()
    assert len(peers) == 2
    assert {peer.device_id for peer in peers} == {first.id, second.id}
    assert {peer.user_id for peer in peers} == {user.id}
    assert len({peer.psk_key for peer in peers}) == 2


async def test_effective_limit_defaults_to_unlimited_for_local_users(db: AsyncSession) -> None:
    user = await _make_user(db)

    assert await effective_device_limit(db, user.id) is None

    user.device_limit = 3
    await db.commit()
    assert await effective_device_limit(db, user.id) == 3


async def test_effective_limit_for_remnawave_users_uses_only_imported_hwid_limit(
    db: AsyncSession,
) -> None:
    from app.models import RemnawaveUser

    user = await _make_user(db)
    user.device_limit = 1  # must be ignored for Remnawave-managed users
    db.add(
        RemnawaveUser(
            id='rw-1',
            user_id=user.id,
            remnawave_uuid='uuid-1',
            username='alice',
            status='ACTIVE',
            hwid_device_limit=5,
        )
    )
    await db.commit()

    assert await effective_device_limit(db, user.id) == 5

    row = (await db.execute(select(RemnawaveUser))).scalar_one()
    row.hwid_device_limit = 0
    await db.commit()
    assert await effective_device_limit(db, user.id) is None

    row.hwid_device_limit = None
    await db.commit()
    assert await effective_device_limit(db, user.id) is None


async def test_device_limit_blocks_further_devices_and_counts_pending_ones(
    db: AsyncSession,
) -> None:
    await _make_node(db)
    user = await _make_user(db)
    user.device_limit = 2
    await db.commit()

    await create_device(db, user.id, name='laptop')
    second, _ = await create_device(db, user.id, name='phone')
    await db.commit()
    assert await count_live_devices(db, user.id) == 2

    with pytest.raises(DeviceLimitExceededError):
        await create_device(db, user.id, name='tablet')

    # deleting a device frees the slot immediately, even though its identity is reserved
    await delete_device(db, second)
    await db.commit()
    assert await count_live_devices(db, user.id) == 1

    third, _ = await create_device(db, user.id, name='tablet')
    await db.commit()
    assert third.deleted_at is None
    assert await count_live_devices(db, user.id) == 2


async def test_delete_device_tombstones_but_keeps_peers_and_history(db: AsyncSession) -> None:
    await _make_node(db, 'node-1')
    await _make_node(db, 'node-2')
    user = await _make_user(db)
    device, _ = await create_device(db, user.id, name='laptop')
    peer = (
        await db.execute(select(Peer).where(Peer.device_id == device.id, Peer.node_id == 'node-1'))
    ).scalar_one()
    peer.status = 'active'
    peer.raw_rx = 1234
    psk_keys = {
        row.psk_key
        for row in (await db.execute(select(Peer).where(Peer.device_id == device.id))).scalars()
    }
    db.add(
        LocalAmneziawgUserLifetimeTraffic(
            user_id=user.id, rx_bytes=100, tx_bytes=20, total_bytes=120
        )
    )
    await db.commit()
    device_ip = device.vpn_ip
    device_id = device.id

    affected = await delete_device(db, device)
    await db.commit()

    assert affected == {'node-1', 'node-2'}
    assert device.deleted_at is not None
    assert device.vpn_ip == device_ip

    peers = (await db.execute(select(Peer).where(Peer.device_id == device_id))).scalars().all()
    assert len(peers) == 2
    assert {peer.status for peer in peers} == {'pending_delete'}
    assert {peer.psk_key for peer in peers} == psk_keys

    traffic = (await db.execute(select(LocalAmneziawgUserLifetimeTraffic))).scalar_one()
    assert traffic.total_bytes == 120

    # repeated deletion is idempotent and reports no extra work
    assert await delete_device(db, device) == set()
    await db.commit()


async def test_a_deleted_device_address_is_reserved_until_every_peer_is_confirmed_gone(
    db: AsyncSession,
) -> None:
    """The finite pool gives an address back only after the node confirms the peer is gone.

    One node's confirmation is never enough: an unreachable node may still hold the address, so
    handing it to a new device would put two tunnels on one address.
    """
    await _make_node(db, 'node-1')
    await _make_node(db, 'node-2')
    user = await _make_user(db)
    first, _ = await create_device(db, user.id, name='laptop')
    await db.commit()
    taken_ip = first.vpn_ip
    first_id = first.id
    keys = (first.public_key, first.private_key)
    psk_keys = {
        peer.psk_key
        for peer in (await db.execute(select(Peer).where(Peer.device_id == first_id))).scalars()
    }

    await delete_device(db, first)
    await db.commit()

    # still unacknowledged: the address stays out of the pool and off any other device
    second, _ = await create_device(db, user.id, name='laptop-2')
    await db.commit()
    assert second.vpn_ip != taken_ip
    assert first.vpn_ip == taken_ip
    assert first.released_vpn_ip is None
    assert await _device_ips(db) >= {taken_ip, second.vpn_ip}

    peers = (
        (await db.execute(select(Peer).where(Peer.device_id == first_id).order_by(Peer.node_id)))
        .scalars()
        .all()
    )
    assert [peer.status for peer in peers] == ['pending_delete', 'pending_delete']

    peers[0].status = 'deleted'
    await db.commit()
    assert await release_device_ips(db, [first_id], at=datetime(2026, 9, 12, tzinfo=UTC)) == set()
    await db.commit()
    assert first.vpn_ip == taken_ip
    assert first.released_vpn_ip is None

    peers[1].status = 'deleted'
    await db.commit()
    released = await release_device_ips(db, [first_id], at=datetime(2026, 9, 12, tzinfo=UTC))
    await db.commit()

    assert released == {first_id}
    assert first.vpn_ip is None
    assert first.released_vpn_ip == taken_ip
    assert first.ip_released_at == datetime(2026, 9, 12, tzinfo=UTC)
    # identity, keys, peer rows and PSKs survive: only the address moved
    assert first.deleted_at is not None
    assert (first.public_key, first.private_key) == keys
    assert {peer.psk_key for peer in peers} == psk_keys
    assert len(peers) == 2


async def test_a_tombstoned_device_without_peers_releases_its_address_at_once(
    db: AsyncSession,
) -> None:
    """A device that never reached a node has nothing to wait for."""
    node = await _make_node(db)
    user = await _make_user(db)
    device, _ = await create_device(db, user.id, name='laptop')
    await db.commit()
    taken_ip = device.vpn_ip
    await _clear_node_peers(db, node.id)

    await delete_device(db, device)
    await db.commit()

    assert device.vpn_ip is None
    assert device.released_vpn_ip == taken_ip
    assert device.ip_released_at is not None


async def test_a_blocked_owner_whose_device_is_still_live_never_releases_its_address(
    db: AsyncSession,
) -> None:
    """Blocking is not deletion: a live device keeps its address even with every peer removed."""
    await _make_node(db)
    user = await _make_user(db)
    device, _ = await create_device(db, user.id, name='laptop')
    await db.commit()
    taken_ip = device.vpn_ip
    user.is_blocked = True
    for peer in (await db.execute(select(Peer).where(Peer.device_id == device.id))).scalars():
        peer.status = 'deleted'
    await db.commit()

    assert await release_device_ips(db, [device.id]) == set()
    await db.commit()
    assert device.vpn_ip == taken_ip
    assert device.released_vpn_ip is None


async def test_a_released_address_is_handed_out_again_with_fresh_key_material(
    db: AsyncSession,
) -> None:
    """Reuse is the point of the release, and it never re-uses the deleted device's keys."""
    await _make_node(db)
    user = await _make_user(db)
    first, _ = await create_device(db, user.id, name='laptop')
    await db.commit()
    taken_ip = first.vpn_ip
    keys = (first.public_key, first.private_key)
    psk_keys = {
        peer.psk_key
        for peer in (await db.execute(select(Peer).where(Peer.device_id == first.id))).scalars()
    }

    await delete_device(db, first)
    for peer in (await db.execute(select(Peer).where(Peer.device_id == first.id))).scalars():
        peer.status = 'deleted'
    await db.commit()
    assert await release_device_ips(db, [first.id]) == {first.id}
    await db.commit()

    second, _ = await create_device(db, user.id, name='phone')
    await db.commit()

    assert second.vpn_ip == taken_ip
    assert (second.public_key, second.private_key) != keys
    assert (first.public_key, first.private_key) == keys
    assert first.released_vpn_ip == taken_ip
    assert {
        peer.psk_key
        for peer in (await db.execute(select(Peer).where(Peer.device_id == first.id))).scalars()
    } == psk_keys


async def test_a_migrated_legacy_address_is_reserved_by_its_device_not_the_user_column(
    db: AsyncSession,
) -> None:
    """Migration 0019 copies each legacy per-user address onto that account's Default device.

    The device is what reserves the address afterwards, so the allocator reads ``devices.vpn_ip``.
    """
    await _make_node(db)
    db.add(User(id='legacy-1', name='legacy', public_key='p', private_key='k', vpn_ip='10.8.0.2'))
    db.add(
        Device(
            id='device-legacy',
            user_id='legacy-1',
            name='Default',
            public_key='legacy-pub',
            private_key='legacy-priv',
            vpn_ip='10.8.0.2',
            is_legacy_default=True,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    await db.commit()
    user = await _make_user(db, 'user-1', 'alice')

    device, _ = await create_device(db, user.id, name='laptop')
    await db.commit()

    assert device.vpn_ip == '10.8.0.3'


async def test_the_frozen_legacy_user_column_never_blocks_reuse_after_a_release(
    db: AsyncSession,
) -> None:
    """``users.vpn_ip`` is history after 0019: it must not reserve an address forever.

    The Default device is the only record that reserves anything, so once that device's address is
    released the pool hands it out again even though the frozen user row still names it.
    """
    await _make_node(db)
    db.add(User(id='legacy-1', name='legacy', public_key='p', private_key='k', vpn_ip='10.8.0.2'))
    db.add(
        Device(
            id='device-legacy',
            user_id='legacy-1',
            name='Default',
            public_key='legacy-pub',
            private_key='legacy-priv',
            vpn_ip='10.8.0.2',
            is_legacy_default=True,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    await db.commit()

    legacy_device = await db.get(Device, 'device-legacy')
    assert legacy_device is not None
    await delete_device(db, legacy_device)
    await db.commit()
    # nothing was ever on a node, so the tombstone released the address right away
    assert legacy_device.vpn_ip is None
    assert legacy_device.released_vpn_ip == '10.8.0.2'
    assert await release_device_ips(db, ['device-legacy']) == set()  # idempotent
    await db.commit()
    assert await db.get(User, 'legacy-1') is not None

    user = await _make_user(db, 'user-1', 'alice')
    device, _ = await create_device(db, user.id, name='laptop')
    await db.commit()

    assert device.vpn_ip == '10.8.0.2'


async def test_device_ip_conflict_is_retried_within_bounded_attempts(
    db: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _make_node(db)
    first_user = await _make_user(db, 'user-1', 'alice')
    first, _ = await create_device(db, first_user.id, name='laptop')
    await db.commit()

    calls = {'count': 0}

    def flaky(used: set[str]) -> str:
        calls['count'] += 1
        if calls['count'] == 1:
            return str(first.vpn_ip)
        return crypto_allocate_ip(used)

    monkeypatch.setattr('app.services.devices.allocate_ip', flaky)

    second_user = await _make_user(db, 'user-2', 'bob')
    second, _ = await create_device(db, second_user.id, name='laptop')
    await db.commit()

    assert second.vpn_ip != first.vpn_ip
    assert calls['count'] >= 2


async def test_device_ip_conflict_gives_up_after_bounded_attempts(
    db: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _make_node(db)
    first_user = await _make_user(db, 'user-1', 'alice')
    first, _ = await create_device(db, first_user.id, name='laptop')
    await db.commit()

    monkeypatch.setattr('app.services.devices.allocate_ip', lambda _used: str(first.vpn_ip))

    second_user = await _make_user(db, 'user-2', 'bob')
    with pytest.raises(DeviceIpAllocationError):
        await create_device(db, second_user.id, name='laptop')


async def test_pending_peers_for_node_only_cover_live_devices(db: AsyncSession) -> None:
    node = await _make_node(db)
    live_user = await _make_user(db, 'user-live', 'live')
    live_device, _ = await create_device(db, live_user.id, name='laptop')
    await db.commit()

    deleted_user = await _make_user(db, 'user-deleted', 'deleted')
    deleted_device, _ = await create_device(db, deleted_user.id, name='laptop')
    await delete_device(db, deleted_device)

    blocked_user = await _make_user(db, 'user-blocked', 'blocked')
    # the device exists first: creating one for an already blocked account is refused by policy
    await create_device(db, blocked_user.id, name='laptop')
    blocked_user.is_blocked = True
    await db.commit()

    # start from an empty node so the test observes exactly what node provisioning creates
    await _clear_node_peers(db, node.id)

    created = await create_pending_peers_for_node(db, node)
    await db.commit()

    assert created == {live_device.id}
    peers = (await db.execute(select(Peer).where(Peer.node_id == node.id))).scalars().all()
    assert {peer.device_id for peer in peers} == {live_device.id}


async def test_pending_peers_for_device_are_idempotent_and_concurrency_safe(
    db: AsyncSession,
) -> None:
    node = await _make_node(db)
    user = await _make_user(db)
    device, _ = await create_device(db, user.id, name='laptop')
    await db.commit()
    await _clear_node_peers(db, node.id)

    session_factory = async_sessionmaker(bind=db.bind, expire_on_commit=False)

    async def create_once() -> set[str]:
        async with session_factory() as session:
            loaded = await session.get(Device, device.id)
            created = await create_pending_peers_for_device(session, loaded)
            await session.commit()
            return created

    first, second = await asyncio.gather(create_once(), create_once())

    peers = (await db.execute(select(Peer).where(Peer.node_id == node.id))).scalars().all()
    assert len(peers) == 1
    assert sorted([first, second], key=len) == [set(), {node.id}]


async def test_live_devices_exclude_blocked_users_and_deleted_devices(db: AsyncSession) -> None:
    await _make_node(db)
    user = await _make_user(db, 'user-1', 'alice')
    device, _ = await create_device(db, user.id, name='laptop')
    await db.commit()

    assert [d.id for d in await list_live_devices(db, user.id)] == [device.id]

    await delete_device(db, device)
    await db.commit()
    assert await list_live_devices(db, user.id) == []


async def test_legacy_default_device_lookup(db: AsyncSession) -> None:
    user = await _make_user(db)
    assert await get_legacy_default_device(db, user.id) is None

    legacy = Device(
        id='device-legacy',
        user_id=user.id,
        name='Default',
        public_key='legacy-pub',
        private_key='legacy-priv',
        vpn_ip='10.8.0.2',
        is_legacy_default=True,
        created_at=datetime.now(UTC),
    )
    other = Device(
        id='device-other',
        user_id=user.id,
        name='phone',
        public_key='other-pub',
        private_key='other-priv',
        vpn_ip='10.8.0.3',
        created_at=datetime.now(UTC),
    )
    db.add_all([legacy, other])
    await db.commit()

    found = await get_legacy_default_device(db, user.id)
    assert found is not None
    assert found.id == 'device-legacy'


async def test_create_pending_peer_refuses_a_tombstoned_device(db: AsyncSession) -> None:
    """A direct call must not provision for a deleted device, not only node enumeration."""
    node = await _make_node(db)
    user = await _make_user(db)
    device, _ = await create_device(db, user.id, name='laptop')
    await db.commit()

    await delete_device(db, device)
    await db.commit()
    await _clear_node_peers(db, node.id)

    assert await create_pending_peer(db, node_id=node.id, device=device) is False
    await db.commit()
    assert (await db.execute(select(Peer).where(Peer.node_id == node.id))).scalars().all() == []


async def test_device_tombstone_outranks_a_stale_live_peer_status(db: AsyncSession) -> None:
    """``Device.deleted_at`` is authoritative: a stale writer cannot un-delete its peers."""
    node = await _make_node(db)
    user = await _make_user(db)
    device, _ = await create_device(db, user.id, name='laptop')
    await db.commit()
    peer = (
        await db.execute(select(Peer).where(Peer.device_id == device.id, Peer.node_id == node.id))
    ).scalar_one()
    peer.status = 'active'
    await db.commit()

    await delete_device(db, device)
    await db.commit()

    # a stale in-flight writer puts the peer back to a live status after the tombstone committed
    peer.status = 'active'
    await db.commit()

    affected = await delete_device(db, device)
    await db.commit()

    assert affected == {node.id}
    assert peer.status == 'pending_delete'
    assert device.deleted_at is not None


async def test_local_block_outranks_a_remnawave_active_profile(db: AsyncSession) -> None:
    """A locally blocked Remnawave owner stays blocked after the public preguard.

    The public add route refuses a blocked owner before it locks the owner row; the write guard that
    re-decides *under* the lock must reach the same answer for an imported profile that still says
    ACTIVE, otherwise the race it exists for provisions a device for a blocked account.
    """
    user = await _make_user(db, 'user-rw', 'rw')
    db.add(RemnawaveUser(user_id=user.id, remnawave_uuid='uuid-rw', username='rw', status='ACTIVE'))
    await db.commit()

    assert await fresh_account_status(db, user.id) == {'code': 'active', 'reason': None}

    user.is_blocked = True
    await db.commit()

    assert await fresh_account_status(db, user.id) == {'code': 'blocked', 'reason': 'blocked'}
    with pytest.raises(AccountInactiveError):
        await create_device(db, user.id, name='laptop')
    assert (await db.execute(select(Device).where(Device.user_id == user.id))).scalars().all() == []


def _exhausted_pool(_used: set[str]) -> str:
    """The finite subnet cannot hand out an address: what ``app.crypto.allocate_ip`` raises."""
    raise RuntimeError('VPN subnet 10.8.0.0/24 is exhausted')


async def test_a_full_address_pool_is_a_typed_error_and_writes_nothing(
    db: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pool exhaustion is expected and must not leak a raw ``RuntimeError``."""
    await _make_node(db)
    user = await _make_user(db)
    user_id = user.id
    monkeypatch.setattr('app.services.devices.allocate_ip', _exhausted_pool)

    with pytest.raises(DeviceIpPoolExhaustedError, match='exhausted'):
        await create_device(db, user_id, name='laptop')

    await db.rollback()
    assert (await db.execute(select(Device).where(Device.user_id == user_id))).scalars().all() == []
    assert (await db.execute(select(Peer).where(Peer.user_id == user_id))).scalars().all() == []
