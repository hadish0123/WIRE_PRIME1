"""Deterministic PostgreSQL regression tests for the owner -> device -> peer lock order.

SQLite has no row locks (``SELECT ... FOR UPDATE`` is a silent no-op there), so the lock-order
regression between a node result (sync/heartbeat) and a device deletion cannot be observed on it:
the two transactions only deadlock when the database really serializes rows. These tests therefore
need a live PostgreSQL server and are opt-in:

- they run only when ``AMNEZIA_TEST_POSTGRES_URL`` names an explicit throwaway test database;
- the ambient ``DATABASE_URL`` is refused, and so is any database whose name does not contain
  ``test``;
- every test creates one randomly named schema (the only object it touches) and drops it again.

Example::

    AMNEZIA_TEST_POSTGRES_URL=postgresql+asyncpg://user:pass@127.0.0.1:54329/amnezia_lock_test \\
        uv run pytest tests/test_postgres_lock_ordering.py -q
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.database import Base
from app.models import (
    AsyncOperation,
    Device,
    LocalAmneziawgUserLifetimeTraffic,
    Node,
    Peer,
    RemnawaveUser,
    User,
)
from app.routers.api_parts import nodes as api_nodes_router
from app.routers.internal_worker_parts import nodes as nodes_router
from app.routers.user_page import DeviceCreate, pub_add_device
from app.schemas.worker import HeartbeatResult, PeerSyncResult, SyncResult
from app.services import devices as devices_service, node_sync
from app.services.devices import (
    DeviceLimitExceededError,
    count_live_devices,
    create_device,
    delete_device,
)
from app.services.node_sync import load_node_with_peers

TEST_DATABASE_URL_ENV = 'AMNEZIA_TEST_POSTGRES_URL'

# Both transactions must finish long before this; a deadlock or an unbroken wait fails the test.
TASK_TIMEOUT_SECONDS = 20
LOCK_TIMEOUT = '4s'
# Time the blocked transaction is given to reach its first lock wait before the holder continues.
BLOCK_SETTLE_SECONDS = 0.3


def _validate_test_database_url(url: str, *, ambient: str | None) -> str:
    """Return a URL only if it is an explicit, dedicated test database.

    Refuses anything that is not PostgreSQL, anything identical to the ambient ``DATABASE_URL`` and
    any database whose name does not contain ``test``.
    """
    if not url.startswith(('postgresql+asyncpg://', 'postgresql://')):
        raise ValueError(f'not a PostgreSQL URL: {url!r}')
    if ambient and url == ambient:
        raise ValueError('refusing to run against the ambient DATABASE_URL')
    database = url.rsplit('/', 1)[-1].split('?', 1)[0].strip()
    if 'test' not in database:
        raise ValueError(
            f'refusing to run against database {database!r}: its name must contain test'
        )
    return url


@pytest.fixture()
def test_database_url() -> str:
    url = os.environ.get(TEST_DATABASE_URL_ENV)
    if not url:
        pytest.skip(f'{TEST_DATABASE_URL_ENV} is not set: PostgreSQL lock order tests are opt-in')
    try:
        return _validate_test_database_url(url, ambient=os.environ.get('DATABASE_URL'))
    except ValueError as exc:  # pragma: no cover - guard rail
        pytest.fail(str(exc))


@pytest.fixture()
async def pg_engine(test_database_url: str) -> AsyncGenerator[AsyncEngine]:
    """A throwaway PostgreSQL schema with the ORM schema created inside it."""
    schema = f'lock_order_{uuid.uuid4().hex[:12]}'
    engine = create_async_engine(
        test_database_url, connect_args={'server_settings': {'search_path': schema}}
    )
    async with engine.begin() as conn:
        await conn.execute(text(f'CREATE SCHEMA {schema}'))
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield engine
    finally:
        async with engine.begin() as conn:
            await conn.execute(text(f'DROP SCHEMA {schema} CASCADE'))
        await engine.dispose()


@pytest.fixture()
def pg_sessions(pg_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(pg_engine, expire_on_commit=False)


async def _seed_node_with_device_peer(session_factory: async_sessionmaker[AsyncSession]) -> None:
    async with session_factory() as session:
        session.add_all(
            [
                Node(id='node-1', name='node-1', url='http://agent:8000', token='node-token'),  # noqa: S106
                # A limit the reported traffic exceeds, so the result really writes the owner row
                # (lifecycle status/blocked flag) instead of leaving it untouched.
                User(id='user-1', name='alice', traffic_limit_bytes=100),
                Device(
                    id='device-1',
                    user_id='user-1',
                    name='Default',
                    public_key='device-pub',
                    private_key='device-priv',
                    vpn_ip='10.8.0.2',
                ),
                Peer(
                    id='peer-1',
                    node_id='node-1',
                    user_id='user-1',
                    device_id='device-1',
                    status='active',
                    psk_key='peer-psk',
                    raw_rx=0,
                    raw_tx=0,
                ),
            ]
        )
        await session.commit()


# A node result and a device deletion only deadlock when the peer rows are locked *before* the
# owner row: deletion takes owner -> device -> peer, so a result that holds a peer lock while it
# waits for the owner row closes exactly the cycle PostgreSQL reports as SQLSTATE 40P01. A result
# that holds no lock at all cannot close that cycle, which is why the pre-fix lockless read is not
# the regression these tests pin (see _lockless_loader).
PG_DEADLOCK_SQLSTATE = '40P01'
PG_LOCK_NOT_AVAILABLE_SQLSTATE = '55P03'


def _sqlstate(error: BaseException) -> str | None:
    """PostgreSQL SQLSTATE carried by a raised error, if it has one."""
    return getattr(getattr(error, 'orig', None), 'sqlstate', None)


async def _peer_first_loader(db: AsyncSession, node_id: str, *, for_update: bool = False):
    """The intermediate buggy loader: peer rows locked first, no owner and no device lock.

    This is the real peer statement (eager user/device/node) plus ``FOR UPDATE`` and nothing else -
    the shape the lock-order regression had before :func:`app.services.node_sync._lock_owner_rows`
    ran first. It is injected into the router, so the orchestration under test stays unchanged.
    """
    node = await db.get(Node, node_id)
    if not node:
        raise HTTPException(status_code=404, detail='Node not found')
    statement = node_sync._peers_of_node(node.id)
    if for_update:
        statement = statement.with_for_update().execution_options(populate_existing=True)
    peers = (await db.execute(statement)).scalars().all()
    return node, list(peers)


async def _lockless_loader(db: AsyncSession, node_id: str, *, for_update: bool = False):
    """The pre-fix ``main`` loader: the node's peers are read without any row lock.

    ``main``'s ``load_node_with_peers`` took no ``FOR UPDATE`` and no owner lock (checked in git
    history at the commit before the lock order landed), so this control documents that the pre-fix
    code cannot reproduce the deadlock: with nothing held, the deletion finishes at once and the
    result only waits for rows nobody holds afterwards.
    """
    del for_update  # main had no such parameter; accepted so the router's call shape matches
    node = await db.get(Node, node_id)
    if not node:
        raise HTTPException(status_code=404, detail='Node not found')
    peers = (await db.execute(node_sync._peers_of_node(node.id))).scalars().all()
    return node, list(peers)


async def _run_result_versus_device_delete(
    sessions: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    *,
    endpoint: str,
    loader: Callable[..., Awaitable[Any]] | None = None,
) -> list[BaseException]:
    """Run one node result and one device deletion concurrently; return each task's error, if any.

    The result transaction is paused inside ``apply_peer_result``, i.e. after the loader returned
    and therefore holding exactly the row locks that loader took. The deletion then starts, and the
    result is released one settle period later. Both tasks must settle within the timeout; what they
    raised (nothing on the ordered loader, the deadlock on the peer-first one) is returned in task
    order. ``monkeypatch`` is the per-test fixture, so every patch it holds is undone at teardown.
    """
    entered = asyncio.Event()
    release = asyncio.Event()
    real_apply_peer_result = nodes_router.apply_peer_result

    async def paused_apply_peer_result(db, peer, data, now):
        entered.set()
        await release.wait()
        return await real_apply_peer_result(db, peer, data, now)

    monkeypatch.setattr(nodes_router, 'apply_peer_result', paused_apply_peer_result)
    # Breaking the traffic limit queues a node sync; the broker is not part of these tests.
    monkeypatch.setattr('app.routers.internal_worker.enqueue_sync_node', AsyncMock())
    if loader is not None:
        monkeypatch.setattr(nodes_router, 'load_node_with_peers', loader)

    peer_result = PeerSyncResult(
        public_key='device-pub', status='active', rx_bytes=4096, tx_bytes=1024
    )

    async def run_node_result() -> None:
        async with sessions() as session:
            await session.execute(text(f"SET lock_timeout = '{LOCK_TIMEOUT}'"))
            if endpoint == 'sync-result':
                await nodes_router.node_sync_result(
                    'node-1', SyncResult(ok=True, peers=[peer_result]), session
                )
            else:
                await nodes_router.node_heartbeat_result(
                    'node-1', HeartbeatResult(ok=True, peers=[peer_result]), session
                )

    async def run_device_delete() -> None:
        await entered.wait()
        async with sessions() as session:
            await session.execute(text(f"SET lock_timeout = '{LOCK_TIMEOUT}'"))
            device = await session.get(Device, 'device-1')
            assert device is not None
            await delete_device(session, device)
            await session.commit()

    result_task = asyncio.create_task(run_node_result())
    await asyncio.wait_for(entered.wait(), TASK_TIMEOUT_SECONDS)
    delete_task = asyncio.create_task(run_device_delete())
    await asyncio.sleep(BLOCK_SETTLE_SECONDS)
    release.set()

    outcomes = await asyncio.wait_for(
        asyncio.gather(result_task, delete_task, return_exceptions=True), TASK_TIMEOUT_SECONDS
    )
    return [outcome for outcome in outcomes if isinstance(outcome, BaseException)]


def test_guard_refuses_ambient_and_non_test_databases() -> None:
    """The opt-in guard must never fall back to the application's own database."""
    good = 'postgresql+asyncpg://u:p@127.0.0.1:5432/amnezia_lock_test'
    assert (
        _validate_test_database_url(good, ambient='postgresql+asyncpg://u:p@db:5432/amnezia')
        == good
    )

    with pytest.raises(ValueError, match='ambient'):
        _validate_test_database_url(good, ambient=good)
    with pytest.raises(ValueError, match='must contain test'):
        _validate_test_database_url('postgresql+asyncpg://u:p@127.0.0.1:5432/amnezia', ambient=None)
    with pytest.raises(ValueError, match='not a PostgreSQL URL'):
        _validate_test_database_url('sqlite+aiosqlite:///./amnezia_test.db', ambient=None)


@pytest.mark.parametrize('endpoint', ['sync-result', 'heartbeat-result'])
async def test_node_result_and_device_delete_deadlock_free(
    pg_sessions: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch, endpoint: str
) -> None:
    """A node result and a device deletion must not deadlock on the owner/peer rows.

    The result transaction is paused while it holds its row locks, the deletion is started
    afterwards, and both are then required to finish. Under the reversed lock order the result
    transaction locks the peer rows first and the deletion the owner row first, so the result's
    later owner write waits on the deletion while the deletion waits on the held peer row - a real
    PostgreSQL deadlock. With the owner row taken before the peer rows there is nothing to wait
    for. The peer-first order is not merely described here either:
    :func:`test_peer_first_loader_deadlocks_on_postgres` injects it into the same orchestration and
    asserts the real 40P01, so this assertion is demonstrated to fail if that order returns.
    """
    await _seed_node_with_device_peer(pg_sessions)

    errors = await _run_result_versus_device_delete(pg_sessions, monkeypatch, endpoint=endpoint)
    assert errors == [], f'the ordered loader must not deadlock: {errors!r}'

    async with pg_sessions() as session:
        device = await session.get(Device, 'device-1')
        peer = await session.get(Peer, 'peer-1')
    assert device is not None and peer is not None
    # the result landed (its traffic was applied) ...
    assert peer.raw_rx == 4096
    # ... and the deletion that ran after it still owns the final state
    assert device.deleted_at is not None
    assert peer.status in {'pending_delete', 'deleted'}


async def test_concurrent_last_slot_device_creation_serializes_on_the_owner(
    pg_sessions: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """One free slot and two simultaneous creations: exactly one device must be created.

    The first creation is paused while it holds the owner row lock, so the second is forced to wait
    on that same row instead of counting the same free slot. The paused call is released afterwards:
    both creations must finish, one with a device and one with a limit error, and only one live
    device may exist.
    """
    async with pg_sessions() as session:
        session.add_all(
            [
                Node(id='node-1', name='node-1', url='http://agent:8000', token='node-token'),  # noqa: S106
                User(id='user-1', name='alice', device_limit=1),
            ]
        )
        await session.commit()

    holding = asyncio.Event()
    release = asyncio.Event()
    real_assert_capacity = devices_service.assert_device_capacity
    state = {'gated': False}

    async def gated_assert_capacity(db, user_id):
        if not state['gated']:
            state['gated'] = True
            holding.set()
            await release.wait()
        return await real_assert_capacity(db, user_id)

    monkeypatch.setattr(devices_service, 'assert_device_capacity', gated_assert_capacity)

    async def attempt(name: str) -> str:
        async with pg_sessions() as session:
            await session.execute(text(f"SET lock_timeout = '{LOCK_TIMEOUT}'"))
            try:
                await create_device(session, 'user-1', name=name)
            except DeviceLimitExceededError:
                await session.rollback()
                return 'limit'
            await session.commit()
            return 'created'

    first_task = asyncio.create_task(attempt('laptop'))
    await asyncio.wait_for(holding.wait(), TASK_TIMEOUT_SECONDS)
    second_task = asyncio.create_task(attempt('phone'))
    await asyncio.sleep(BLOCK_SETTLE_SECONDS)
    release.set()

    outcomes = await asyncio.wait_for(asyncio.gather(first_task, second_task), TASK_TIMEOUT_SECONDS)
    assert sorted(outcomes) == ['created', 'limit']

    async with pg_sessions() as session:
        assert await count_live_devices(session, 'user-1') == 1
        peers = (
            (await session.execute(select(Peer).where(Peer.user_id == 'user-1'))).scalars().all()
        )
    assert len(peers) == 1


async def test_peer_created_while_the_result_waits_is_left_to_the_next_result(
    pg_sessions: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A peer that appears while the result waits must not pull an unlocked owner into the locks.

    The result transaction is paused after it locked its owners and peers; a second transaction then
    creates a device - and therefore a peer on the same node - for a different, unlocked user. The
    result must finish without writing the newcomer or taking its owner's lock, and the newcomer
    must still be pending and then be picked up by the next result for the node.
    """
    await _seed_node_with_device_peer(pg_sessions)
    async with pg_sessions() as session:
        session.add(User(id='user-2', name='bob'))
        await session.commit()

    entered = asyncio.Event()
    release = asyncio.Event()
    real_apply_peer_result = nodes_router.apply_peer_result

    async def paused_apply_peer_result(db, peer, data, now):
        entered.set()
        await release.wait()
        return await real_apply_peer_result(db, peer, data, now)

    monkeypatch.setattr(nodes_router, 'apply_peer_result', paused_apply_peer_result)
    monkeypatch.setattr('app.routers.internal_worker.enqueue_sync_node', AsyncMock())

    peer_result = PeerSyncResult(
        public_key='device-pub', status='active', rx_bytes=4096, tx_bytes=1024
    )

    async def run_node_result() -> None:
        async with pg_sessions() as session:
            await session.execute(text(f"SET lock_timeout = '{LOCK_TIMEOUT}'"))
            await nodes_router.node_sync_result(
                'node-1', SyncResult(ok=True, peers=[peer_result]), session
            )

    async def create_late_device() -> str:
        await entered.wait()
        async with pg_sessions() as session:
            await session.execute(text(f"SET lock_timeout = '{LOCK_TIMEOUT}'"))
            device, _ = await create_device(session, 'user-2', name='late')
            await session.commit()
            public_key = device.public_key
        assert public_key is not None
        return public_key

    result_task = asyncio.create_task(run_node_result())
    await asyncio.wait_for(entered.wait(), TASK_TIMEOUT_SECONDS)
    late_task = asyncio.create_task(create_late_device())
    await asyncio.sleep(BLOCK_SETTLE_SECONDS)
    release.set()

    await asyncio.wait_for(asyncio.gather(result_task, late_task), TASK_TIMEOUT_SECONDS)
    late_public_key = late_task.result()

    async with pg_sessions() as session:
        late_peer = (
            await session.execute(select(Peer).where(Peer.user_id == 'user-2'))
        ).scalar_one()
    # the paused result never wrote the newcomer: no status change and no traffic
    assert late_peer.status == 'pending'
    assert late_peer.raw_rx is None

    async with pg_sessions() as session:
        await nodes_router.node_sync_result(
            'node-1',
            SyncResult(
                ok=True,
                peers=[
                    PeerSyncResult(
                        public_key=late_public_key, status='active', rx_bytes=777, tx_bytes=42
                    )
                ],
            ),
            session,
        )
    async with pg_sessions() as session:
        late_peer = (
            await session.execute(select(Peer).where(Peer.user_id == 'user-2'))
        ).scalar_one()
    assert late_peer.raw_rx == 777
    assert late_peer.status == 'active'


async def test_peer_first_loader_deadlocks_on_postgres(
    pg_sessions: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The regression that produced the RED evidence: peer rows locked before the owner row.

    Same seed and same orchestration as the deadlock-free test; only the router's loader is replaced
    by the intermediate slice that ran ``SELECT Peer ... FOR UPDATE`` first and took no owner lock.
    The result therefore holds the peer row while the deletion holds the owner and device rows and
    waits for that peer: a genuine cycle, which PostgreSQL itself detects and reports as SQLSTATE
    40P01 - not a lock timeout (55P03), and not an arbitrary error. Either of those would fail the
    assertion below instead of passing it.

    The peer-first loader is injected through a context manager, so this test also asserts in-test
    that the injection was really removed again; the ``monkeypatch`` fixture restores its own
    patches (the paused ``apply_peer_result`` and the stubbed enqueue) at teardown.
    """
    await _seed_node_with_device_peer(pg_sessions)

    with pytest.MonkeyPatch.context() as injection:
        injection.setattr(nodes_router, 'load_node_with_peers', _peer_first_loader)
        assert nodes_router.load_node_with_peers is _peer_first_loader
        errors = await _run_result_versus_device_delete(
            pg_sessions, monkeypatch, endpoint='sync-result'
        )

    assert nodes_router.load_node_with_peers is load_node_with_peers

    sqlstates = [(type(error).__name__, _sqlstate(error)) for error in errors]
    assert sqlstates == [('DBAPIError', PG_DEADLOCK_SQLSTATE)], (
        f'the peer-first loader must fail with a real PostgreSQL deadlock '
        f'({PG_DEADLOCK_SQLSTATE}), not a lock timeout ({PG_LOCK_NOT_AVAILABLE_SQLSTATE}) and not '
        f'any other error: {sqlstates}'
    )


async def test_lockless_loader_does_not_deadlock(
    pg_sessions: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pre-fix lockless read is *not* the regression: it holds nothing, so it cannot deadlock.

    ``main``'s loader read the peers with no ``FOR UPDATE`` and took no owner lock (see
    :func:`_lockless_loader`, verified against the commit before the lock order landed). While the
    result is paused it therefore holds no row lock at all, so the deletion takes owner, device and
    peer rows uncontended, and the result only ever waits for rows nobody holds: no cycle, no 40P01.
    The deadlock RED evidence cannot have come from the pre-fix behaviour; it comes from the
    intermediate peer-first slice pinned by
    :func:`test_peer_first_loader_deadlocks_on_postgres`. Both transactions still land here, which
    is why the ordering - not the traffic write - is what the review under discussion is about.
    """
    await _seed_node_with_device_peer(pg_sessions)

    errors = await _run_result_versus_device_delete(
        pg_sessions, monkeypatch, endpoint='sync-result', loader=_lockless_loader
    )
    assert errors == [], f'the lockless read must not raise anything: {errors!r}'

    async with pg_sessions() as session:
        device = await session.get(Device, 'device-1')
        peer = await session.get(Peer, 'peer-1')
    assert device is not None and peer is not None
    assert device.deleted_at is not None
    assert peer.raw_rx == 4096
    assert peer.status in {'pending_delete', 'deleted'}


async def _legacy_delete_node(node_id: str, db: AsyncSession) -> None:
    """The old endpoint order, retained only as a real PostgreSQL deadlock control."""
    node = await db.get(Node, node_id)
    assert node is not None
    device_ids = set(
        (await db.execute(select(Peer.device_id).where(Peer.node_id == node_id))).scalars()
    )
    await db.delete(node)
    await db.flush()
    await api_nodes_router.release_device_ips(db, device_ids)
    await db.commit()


@pytest.mark.parametrize('legacy', [False, True], ids=['ordered-endpoint', 'legacy-40P01'])
async def test_node_delete_versus_device_delete(  # noqa: PLR0915 - keep both lock barriers together
    pg_sessions: async_sessionmaker[AsyncSession],
    pg_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    legacy: bool,
) -> None:
    """Two real writers, gated at their lock boundaries; an observer verifies actual lock waits.

    Device deletion holds User/Device before requesting Peer. The old node endpoint deletes Peer
    before reclaim locks Device, closing a 40P01 cycle. The ordered endpoint instead waits on User
    before deleting anything. No sleep is used as evidence that a writer reached its lock wait.
    """
    await _seed_node_with_device_peer(pg_sessions)
    device_holding = asyncio.Event()
    advance_device = asyncio.Event()
    node_flushed = asyncio.Event()
    advance_node = asyncio.Event()
    node_started = asyncio.Event()
    pids: dict[str, int] = {}
    real_release = api_nodes_router.release_device_ips

    async def gated_release(db, ids):
        node_flushed.set()
        await advance_node.wait()
        return await real_release(db, ids)

    monkeypatch.setattr(api_nodes_router, 'release_device_ips', gated_release)

    async def run_device() -> None:
        async with pg_sessions() as session:
            await session.execute(text(f"SET lock_timeout = '{LOCK_TIMEOUT}'"))
            pids['device'] = await session.scalar(text('SELECT pg_backend_pid()'))
            device = await session.get(Device, 'device-1')
            assert device is not None
            execute = session.execute

            async def gated_execute(statement, *args, **kwargs):
                if (
                    getattr(statement, 'is_select', False)
                    and statement.column_descriptions[0].get('entity') is Peer
                ):
                    device_holding.set()
                    await advance_device.wait()
                return await execute(statement, *args, **kwargs)

            monkeypatch.setattr(session, 'execute', gated_execute)
            await delete_device(session, device)
            await session.commit()

    async def run_node() -> None:
        async with pg_sessions() as session:
            await session.execute(text(f"SET lock_timeout = '{LOCK_TIMEOUT}'"))
            pids['node'] = await session.scalar(text('SELECT pg_backend_pid()'))
            node_started.set()
            endpoint = _legacy_delete_node if legacy else api_nodes_router.api_delete_node
            await endpoint('node-1', session)

    async def blocked_by(waiter: str, holder: str) -> bool:
        async with pg_engine.connect() as observer:
            return bool(
                await observer.scalar(
                    text('SELECT :holder = ANY(pg_blocking_pids(:waiter))'),
                    {'holder': pids[holder], 'waiter': pids[waiter]},
                )
            )

    async def reach_boundary() -> None:
        # PostgreSQL lock waits have no asyncio.Event; poll the server, not an assumed delay.
        while not node_flushed.is_set() and not await blocked_by('node', 'device'):  # noqa: ASYNC110
            await asyncio.sleep(0.01)

    async def device_waits_for_peer() -> None:
        while not await blocked_by('device', 'node'):  # noqa: ASYNC110 - server-side lock state
            await asyncio.sleep(0.01)

    device_task = asyncio.create_task(run_device())
    node_task = None
    try:
        await asyncio.wait_for(device_holding.wait(), TASK_TIMEOUT_SECONDS)
        node_task = asyncio.create_task(run_node())
        await asyncio.wait_for(node_started.wait(), TASK_TIMEOUT_SECONDS)
        await asyncio.wait_for(reach_boundary(), TASK_TIMEOUT_SECONDS)
        advance_device.set()
        if node_flushed.is_set():
            await asyncio.wait_for(device_waits_for_peer(), TASK_TIMEOUT_SECONDS)
        advance_node.set()
        outcomes = await asyncio.wait_for(
            asyncio.gather(device_task, node_task, return_exceptions=True), TASK_TIMEOUT_SECONDS
        )
    finally:
        advance_device.set()
        advance_node.set()
        tasks = [task for task in (device_task, node_task) if task is not None]
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    errors = [outcome for outcome in outcomes if isinstance(outcome, BaseException)]
    sqlstates = [_sqlstate(error) for error in errors]
    if legacy:
        assert sqlstates == [PG_DEADLOCK_SQLSTATE], errors
    else:
        assert errors == [], f'node deletion must not deadlock: SQLSTATE={sqlstates}, {errors!r}'
        async with pg_sessions() as session:
            assert await session.get(Node, 'node-1') is None
            assert await session.get(Peer, 'peer-1') is None
            device = await session.get(Device, 'device-1')
            assert device is not None and device.deleted_at is not None
            assert device.vpn_ip is None
            assert device.released_vpn_ip == '10.8.0.2'
            assert device.ip_released_at is not None


async def _seed_owner_for_account_policy(
    session_factory: async_sessionmaker[AsyncSession], *, remnawave: bool
) -> None:
    """A node plus an active owner whose local traffic limit is reachable by one traffic row."""
    async with session_factory() as session:
        session.add_all(
            [
                Node(id='node-1', name='node-1', url='http://agent:8000', token='node-token'),  # noqa: S106
                User(id='user-1', name='alice', traffic_limit_bytes=100),
            ]
        )
        if remnawave:
            session.add(
                RemnawaveUser(
                    id='rw-user-1',
                    user_id='user-1',
                    remnawave_uuid='rw-uuid-1',
                    username='alice',
                    status='ACTIVE',
                )
            )
        await session.commit()


# The committed state the holder writes, and the HTTP answer the add route must produce for it.
POLICY_MUTATIONS = {
    'blocked': 'Account is blocked',
    'expired': 'Account is expired',
    'limited': 'Account is limited',
    'remnawave-disabled': 'Account is blocked',
}


@pytest.mark.parametrize('mutation', sorted(POLICY_MUTATIONS))
async def test_device_creation_rechecks_the_account_after_waiting_for_the_owner_lock(
    pg_sessions: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    """A stale active owner must not provision once another session inactivates it.

    The add route's own guard runs before the owner row lock, so it can be raced: this session maps
    the owner (and, for the Remnawave case, its profile) as active, then blocks inside
    ``create_device`` on the owner row the holder locked. The holder commits the block / expiry /
    local traffic overrun / Remnawave disable and releases the lock. The route must re-read the
    committed state under the lock and answer 403, with no device, peer or queued operation left.
    """
    uses_remnawave = mutation == 'remnawave-disabled'
    await _seed_owner_for_account_policy(pg_sessions, remnawave=uses_remnawave)

    # Provisioning would queue node syncs; the broker is not part of these tests.
    monkeypatch.setattr('app.routers.internal_worker.enqueue_sync_node', AsyncMock())

    holding = asyncio.Event()
    release = asyncio.Event()

    async def hold_lock_then_inactivate() -> None:
        async with pg_sessions() as session:
            await session.execute(text(f"SET lock_timeout = '{LOCK_TIMEOUT}'"))
            owner = (
                await session.execute(select(User).where(User.id == 'user-1').with_for_update())
            ).scalar_one()
            holding.set()
            await release.wait()
            if mutation == 'blocked':
                owner.is_blocked = True
            elif mutation == 'expired':
                owner.expire_at = datetime.now(UTC) - timedelta(days=1)
            elif mutation == 'limited':
                session.add(
                    LocalAmneziawgUserLifetimeTraffic(
                        user_id='user-1', rx_bytes=150, tx_bytes=50, total_bytes=200
                    )
                )
            else:
                profile = (
                    await session.execute(
                        select(RemnawaveUser).where(RemnawaveUser.user_id == 'user-1')
                    )
                ).scalar_one()
                profile.status = 'DISABLED'
            await session.commit()

    async def attempt_add() -> object:
        async with pg_sessions() as session:
            await session.execute(text(f"SET lock_timeout = '{LOCK_TIMEOUT}'"))
            # Stale preload: this session already holds the owner - and its profile - as active
            # before it waits for the lock, which is exactly what the pre-lock guard sees.
            assert await session.get(User, 'user-1') is not None
            if uses_remnawave:
                assert await session.get(RemnawaveUser, 'rw-user-1') is not None
            try:
                await pub_add_device('user-1', DeviceCreate(name='laptop'), session)
            except HTTPException as exc:
                await session.rollback()
                return exc.status_code, exc.detail
            await session.commit()
            return 'created'

    holder = asyncio.create_task(hold_lock_then_inactivate())
    await asyncio.wait_for(holding.wait(), TASK_TIMEOUT_SECONDS)
    adder = asyncio.create_task(attempt_add())
    await asyncio.sleep(BLOCK_SETTLE_SECONDS)
    release.set()

    assert await asyncio.wait_for(adder, TASK_TIMEOUT_SECONDS) == (
        HTTPStatus.FORBIDDEN,
        POLICY_MUTATIONS[mutation],
    )
    await asyncio.wait_for(holder, TASK_TIMEOUT_SECONDS)

    async with pg_sessions() as session:
        assert await count_live_devices(session, 'user-1') == 0
        assert (await session.execute(select(Device))).scalars().all() == []
        assert (await session.execute(select(Peer))).scalars().all() == []
        assert (await session.execute(select(AsyncOperation))).scalars().all() == []
