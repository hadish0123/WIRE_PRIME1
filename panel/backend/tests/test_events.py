"""Change notifications and the public event stream.

Two properties carry this slice, and both are asserted here rather than described in a comment:

- *transactional*: a notification exists only because a transaction that wrote the change
  committed. Nothing is delivered before the commit, nothing at all after a rollback, and the
  serialized payload carries an account id and a reason - never a key, a config body or a profile;
- *authorized per account*: an open stream belongs to one resolved account. Another account's change
  is not delivered to it, its token is re-checked while open, and it is released on disconnect,
  shutdown or a client that stops reading.

The SQLite test database has no ``NOTIFY``, so the commit hook hands the payloads to the in-process
hub. That is the test transport; the real PostgreSQL commit coupling - delivered on commit, dropped
on rollback - is pinned by the opt-in ``test_postgres_notify.py``.

The test transport keeps the same rule for SAVEPOINTs: releasing one raises the commit event, but it
delivers nothing, because only the outermost transaction's commit can reach a client.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from http import HTTPStatus
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.models import Device, Node, Peer, User
from app.routers import user_page as user_page_router
from app.routers.user_events import pub_user_events
from app.routers.user_page import DeviceCreate, pub_add_device
from app.services.events import (
    REASON_DEVICE_CREATED,
    REASON_DEVICE_DELETED,
    REASON_NODE_HEARTBEAT,
    REASON_NODE_SYNC,
    EventStreamsStoppedError,
    StreamTiming,
    SubscriptionLimitExceededError,
    UserEventHub,
    UserEventSubscription,
    asyncpg_dsn,
    configure_hub,
    notify_user_changes,
    user_event_stream,
)

ALICE = 'user-1'
BOB = 'user-2'
ALICE_TOKEN = 'tok-alice'


@pytest.fixture()
def event_hub() -> Any:
    """A hub with no listener: in-process delivery, no coalescing window."""
    hub = UserEventHub(None, coalesce_seconds=0.0)
    configure_hub(hub)
    try:
        yield hub
    finally:
        configure_hub(None)


def _session_factory() -> Any:
    """The factory the app dependency is overridden with, for direct route calls."""
    from tests.conftest import TestSessionLocal

    return TestSessionLocal


async def _drain(subscription: UserEventSubscription, within: float = 0.15) -> list[Any]:
    """Everything the subscription received within ``within`` of the queue going quiet."""
    items: list[Any] = []
    while True:
        try:
            items.append(await asyncio.wait_for(subscription.queue.get(), within))
        except TimeoutError:
            return items


async def _next_frame(stream: Any, within: float = 1.0) -> bytes:
    return await asyncio.wait_for(stream.__anext__(), within)


def _frame_name(frame: bytes) -> str:
    first = frame.decode().splitlines()[0]
    return first[len('event: ') :] if first.startswith('event: ') else first


def _frame_data(frame: bytes) -> dict[str, Any]:
    for line in frame.decode().splitlines():
        if line.startswith('data: '):
            return json.loads(line[len('data: ') :])
    return {}


class _ConnectedClient(Request):
    """A request whose only meaningful answer is whether the client is still there."""

    def __init__(self, *, disconnect_after: int | None = None) -> None:
        super().__init__({'type': 'http', 'headers': []})
        self.checks = 0
        self._disconnect_after = disconnect_after

    async def is_disconnected(self) -> bool:
        self.checks += 1
        if self._disconnect_after is None:
            return False
        return self.checks > self._disconnect_after


async def _close_body(response: Any) -> None:
    await cast(AsyncGenerator[bytes], response.body_iterator).aclose()


async def _always_authorized() -> bool:
    return True


# ── the transport is the PostgreSQL listener, or an explicitly degraded stream ─


class TestAsyncpgDsn:
    def test_accepts_the_postgresql_drivers_and_refuses_everything_else(self) -> None:
        assert (
            asyncpg_dsn('postgresql+asyncpg://amnezia:secret@db:5432/amnezia')
            == 'postgresql://amnezia:secret@db:5432/amnezia'
        )
        assert asyncpg_dsn('postgresql://u:p@db:5432/amnezia') == 'postgresql://u:p@db:5432/amnezia'
        assert asyncpg_dsn('postgres://u:p@db/amnezia') == 'postgres://u:p@db/amnezia'
        # No DSN means "no listener": the streams it serves must report themselves as degraded
        # instead of implying a reliability the process does not have.
        assert asyncpg_dsn('sqlite+aiosqlite:///file::memory:?cache=shared') is None
        assert asyncpg_dsn('') is None
        assert asyncpg_dsn(None) is None


class _UnattachableConnection:
    """A listener connection whose ``add_listener`` fails after ``connect`` already succeeded."""

    def __init__(self) -> None:
        self.closed = False
        self.terminated = False

    async def add_listener(self, channel: str, callback: Any) -> None:
        del callback
        raise RuntimeError(f'cannot listen on {channel}')

    async def close(self) -> None:
        self.closed = True

    def is_closed(self) -> bool:
        return self.closed

    def terminate(self) -> None:
        self.terminated = True
        self.closed = True


async def test_a_listener_that_cannot_attach_does_not_leak_its_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``connect`` succeeding is not enough: a connection that never attached is still closed."""
    connection = _UnattachableConnection()
    monkeypatch.setattr('app.services.events.asyncpg.connect', AsyncMock(return_value=connection))
    hub = UserEventHub('postgresql://u:p@127.0.0.1:1/notify_test', reconnect_backoff=(0.01,))
    await hub.start()
    try:
        for _ in range(200):
            if connection.closed:
                break
            await asyncio.sleep(0.01)
        assert connection.closed is True, 'the failed setup leaked its connection'
        assert hub.available is False
    finally:
        await hub.stop()


# ── transactional delivery ─────────────────────────────────────────────────────


async def test_a_notification_is_delivered_only_once_its_transaction_commits(
    event_hub: UserEventHub, db: AsyncSession
) -> None:
    subscription = event_hub.subscribe(ALICE)

    await notify_user_changes(db, [ALICE], reason=REASON_DEVICE_CREATED)
    assert await _drain(subscription) == [], 'nothing may be delivered before the commit'

    await db.commit()
    assert await _drain(subscription) == [REASON_DEVICE_CREATED]


async def test_a_rolled_back_change_notifies_nobody(
    event_hub: UserEventHub, db: AsyncSession
) -> None:
    subscription = event_hub.subscribe(ALICE)

    await notify_user_changes(db, [ALICE], reason=REASON_DEVICE_CREATED)
    await db.rollback()

    assert await _drain(subscription) == []


async def test_a_savepoint_release_never_notifies_before_the_outer_commit(
    event_hub: UserEventHub, db: AsyncSession
) -> None:
    """Releasing a SAVEPOINT raises the commit event too; it is not the commit a client waits on."""
    subscription = event_hub.subscribe(ALICE)

    async with db.begin_nested():
        await notify_user_changes(db, [ALICE], reason=REASON_DEVICE_CREATED)

    assert await _drain(subscription) == [], 'a savepoint release must notify nobody, yet'

    await db.commit()
    assert await _drain(subscription) == [REASON_DEVICE_CREATED]


async def test_a_rolled_back_savepoint_takes_only_its_own_notification(
    event_hub: UserEventHub, db: AsyncSession
) -> None:
    """The outer transaction keeps its notification; the savepoint's own goes away with it."""
    subscription = event_hub.subscribe(ALICE)

    await notify_user_changes(db, [ALICE], reason=REASON_DEVICE_CREATED)
    savepoint = await db.begin_nested()
    await notify_user_changes(db, [ALICE], reason=REASON_DEVICE_DELETED)
    await savepoint.rollback()

    await db.commit()

    assert await _drain(subscription) == [REASON_DEVICE_CREATED]


async def test_a_transaction_that_was_closed_instead_of_committed_notifies_nobody(
    event_hub: UserEventHub, db: AsyncSession
) -> None:
    """Payloads must not outlive their transaction in a session that is reused afterwards."""
    subscription = event_hub.subscribe(ALICE)
    db.add(User(id=ALICE, name='alice', public_token=ALICE_TOKEN))
    await db.flush()
    await notify_user_changes(db, [ALICE], reason=REASON_DEVICE_CREATED)

    await db.close()

    # A session is reusable: the next commit must not resurrect what the close discarded.
    await db.commit()
    assert await _drain(subscription) == []


async def test_a_notification_reaches_only_the_named_account(
    event_hub: UserEventHub, db: AsyncSession
) -> None:
    alice = event_hub.subscribe(ALICE)
    bob = event_hub.subscribe(BOB)

    await notify_user_changes(db, [ALICE], reason=REASON_DEVICE_DELETED)
    await db.commit()

    assert await _drain(alice) == [REASON_DEVICE_DELETED]
    assert await _drain(bob) == []


async def test_notifying_about_nobody_records_nothing(
    event_hub: UserEventHub, db: AsyncSession
) -> None:
    assert await notify_user_changes(db, [], reason=REASON_NODE_SYNC) == 0
    assert await notify_user_changes(db, ['', ALICE], reason=REASON_NODE_SYNC) == 1
    await db.rollback()
    assert event_hub.subscription_count == 0


async def test_the_serialized_payload_has_no_keys_no_config_and_no_profile(
    event_hub: UserEventHub, db: AsyncSession
) -> None:
    captured: list[str] = []
    original = event_hub.deliver_local

    def spy(payloads: list[str]) -> None:
        captured.extend(payloads)
        original(payloads)

    event_hub.deliver_local = spy  # type: ignore[method-assign]
    subscription = event_hub.subscribe(ALICE)

    await notify_user_changes(db, [ALICE], reason=REASON_DEVICE_CREATED)
    await db.commit()

    assert captured == [json.dumps({'user_id': ALICE, 'reason': REASON_DEVICE_CREATED})]
    for forbidden in ('key', 'psk', 'config', 'vpn_uri', 'public_token', 'ip'):
        assert forbidden not in captured[0]
    assert await _drain(subscription) == [REASON_DEVICE_CREATED]


async def test_extra_fields_in_a_payload_never_reach_the_client(
    event_hub: UserEventHub,
) -> None:
    """A notification is a trigger, not a payload: only the reason is forwarded."""
    subscription = event_hub.subscribe(ALICE)

    event_hub.deliver_payload(
        json.dumps(
            {
                'user_id': ALICE,
                'reason': REASON_NODE_SYNC,
                'private_key': 'SECRET',
                'vpn_uri': 'vpn://SECRET',
            }
        )
    )

    assert await _drain(subscription) == [REASON_NODE_SYNC]


def test_malformed_payloads_are_dropped(event_hub: UserEventHub) -> None:
    event_hub.deliver_payload('not json')
    event_hub.deliver_payload(json.dumps(['user-1']))
    event_hub.deliver_payload(json.dumps({'reason': REASON_NODE_SYNC}))
    assert event_hub.subscription_count == 0


# ── bounded, coalescing fan-out ────────────────────────────────────────────────


async def test_a_burst_of_changes_collapses_into_at_most_two_events() -> None:
    """One event for the burst and one trailing event for the rest of its window, however loud."""
    hub = UserEventHub(None, coalesce_seconds=0.05)
    subscription = hub.subscribe(ALICE)

    for _ in range(20):
        hub.deliver_payload(json.dumps({'user_id': ALICE, 'reason': REASON_NODE_HEARTBEAT}))

    assert await _drain(subscription, within=0.2) == [REASON_NODE_HEARTBEAT, REASON_NODE_HEARTBEAT]


async def test_a_change_outside_the_window_is_delivered_on_its_own() -> None:
    hub = UserEventHub(None, coalesce_seconds=0.05)
    subscription = hub.subscribe(ALICE)

    hub.deliver_payload(json.dumps({'user_id': ALICE, 'reason': REASON_NODE_SYNC}))
    assert await _drain(subscription) == [REASON_NODE_SYNC]

    await asyncio.sleep(0.06)
    hub.deliver_payload(json.dumps({'user_id': ALICE, 'reason': REASON_NODE_SYNC}))

    assert await _drain(subscription) == [REASON_NODE_SYNC]


async def test_a_device_change_is_not_delayed_by_the_coalescing_window() -> None:
    """Only heartbeat traffic is coalesced: a device change reaches the client when it commits."""
    hub = UserEventHub(None, coalesce_seconds=60.0)
    subscription = hub.subscribe(ALICE)

    hub.deliver_payload(json.dumps({'user_id': ALICE, 'reason': REASON_NODE_HEARTBEAT}))
    assert await _drain(subscription, within=0.01) == [REASON_NODE_HEARTBEAT]

    for reason in (REASON_DEVICE_CREATED, REASON_DEVICE_DELETED, REASON_NODE_SYNC):
        hub.deliver_payload(json.dumps({'user_id': ALICE, 'reason': reason}))
        assert await _drain(subscription, within=0.01) == [reason], reason


async def test_every_open_tab_of_one_account_is_notified() -> None:
    hub = UserEventHub(None, coalesce_seconds=0.0)
    first = hub.subscribe(ALICE)
    second = hub.subscribe(ALICE)

    hub.deliver_payload(json.dumps({'user_id': ALICE, 'reason': REASON_DEVICE_CREATED}))

    assert await _drain(first) == [REASON_DEVICE_CREATED]
    assert await _drain(second) == [REASON_DEVICE_CREATED]


async def test_unsubscribing_releases_the_account_and_its_pending_event() -> None:
    hub = UserEventHub(None, coalesce_seconds=0.2)
    subscription = hub.subscribe(ALICE)

    hub.deliver_payload(json.dumps({'user_id': ALICE, 'reason': REASON_NODE_HEARTBEAT}))
    assert await _drain(subscription, within=0.01) == [REASON_NODE_HEARTBEAT]
    assert hub.subscription_count == 1

    # A second heartbeat inside the window books a trailing event; releasing the account has to
    # cancel it.
    hub.deliver_payload(json.dumps({'user_id': ALICE, 'reason': REASON_NODE_HEARTBEAT}))
    hub.unsubscribe(subscription)
    await asyncio.sleep(0.25)

    assert hub.subscription_count == 0
    assert await _drain(subscription, within=0.05) == []
    # a released account is no longer a fan-out target either
    hub.deliver_payload(json.dumps({'user_id': ALICE, 'reason': REASON_NODE_HEARTBEAT}))
    assert await _drain(subscription, within=0.05) == []


def test_the_stream_cap_is_enforced_per_process() -> None:
    hub = UserEventHub(None, max_subscriptions=1)
    hub.subscribe(ALICE)
    with pytest.raises(SubscriptionLimitExceededError):
        hub.subscribe(BOB)


# ── the stream body ────────────────────────────────────────────────────────────

# A stream whose heartbeat is far away: a test awaiting the next frame sees its own event, not a
# keepalive, and the timing constants under test are the ones the test sets explicitly.
QUIET = StreamTiming(heartbeat_seconds=30.0)


async def test_the_stream_opens_with_connected_and_the_listener_state(
    event_hub: UserEventHub,
) -> None:
    subscription = event_hub.subscribe(ALICE)
    stream = user_event_stream(
        subscription, authorize=_always_authorized, hub=event_hub, timing=QUIET
    )

    data = _frame_data(await _next_frame(stream))

    assert data == {'user_id': ALICE, 'notifications': False}
    await stream.aclose()
    assert event_hub.subscription_count == 0


async def test_the_stream_forwards_a_change_without_any_configuration(
    event_hub: UserEventHub,
) -> None:
    subscription = event_hub.subscribe(ALICE)
    stream = user_event_stream(
        subscription, authorize=_always_authorized, hub=event_hub, timing=QUIET
    )
    assert _frame_name(await _next_frame(stream)) == 'connected'

    event_hub.deliver_payload(json.dumps({'user_id': ALICE, 'reason': REASON_NODE_SYNC}))

    frame = await _next_frame(stream)
    assert _frame_name(frame) == 'changed'
    assert _frame_data(frame) == {'reason': REASON_NODE_SYNC}
    await stream.aclose()


async def test_another_accounts_change_never_reaches_this_stream(
    event_hub: UserEventHub,
) -> None:
    """A stream is scoped to the account its token resolved to; that is the whole isolation."""
    subscription = event_hub.subscribe(ALICE)
    stream = user_event_stream(
        subscription, authorize=_always_authorized, hub=event_hub, timing=QUIET
    )
    assert _frame_name(await _next_frame(stream)) == 'connected'

    event_hub.deliver_payload(json.dumps({'user_id': BOB, 'reason': REASON_DEVICE_CREATED}))
    event_hub.deliver_payload(json.dumps({'user_id': ALICE, 'reason': REASON_DEVICE_CREATED}))

    frame = await _next_frame(stream)
    assert _frame_data(frame) == {'reason': REASON_DEVICE_CREATED}
    await stream.aclose()


async def test_a_quiet_stream_keeps_itself_alive_with_a_heartbeat(
    event_hub: UserEventHub,
) -> None:
    subscription = event_hub.subscribe(ALICE)
    stream = user_event_stream(
        subscription,
        authorize=_always_authorized,
        hub=event_hub,
        timing=StreamTiming(heartbeat_seconds=0.05, auth_recheck_seconds=30.0),
    )
    assert _frame_name(await _next_frame(stream)) == 'connected'

    assert await _next_frame(stream) == b': keepalive\n\n'
    await stream.aclose()


async def test_the_stream_closes_once_the_token_stops_resolving(
    event_hub: UserEventHub,
) -> None:
    checks = {'count': 0}

    async def authorize() -> bool:
        checks['count'] += 1
        return checks['count'] == 1

    subscription = event_hub.subscribe(ALICE)
    stream = user_event_stream(
        subscription,
        authorize=authorize,
        hub=event_hub,
        timing=StreamTiming(heartbeat_seconds=30.0, auth_recheck_seconds=0.05),
    )
    assert _frame_name(await _next_frame(stream)) == 'connected'

    frame = await _next_frame(stream)
    assert _frame_name(frame) == 'unauthorized'
    with pytest.raises(StopAsyncIteration):
        await _next_frame(stream)
    assert event_hub.subscription_count == 0


async def test_a_disconnected_client_releases_the_stream(
    event_hub: UserEventHub,
) -> None:
    request = _ConnectedClient(disconnect_after=0)
    subscription = event_hub.subscribe(ALICE)
    stream = user_event_stream(
        subscription,
        authorize=_always_authorized,
        hub=event_hub,
        is_disconnected=request.is_disconnected,
        timing=StreamTiming(heartbeat_seconds=30.0, disconnect_poll_seconds=0.02),
    )
    assert _frame_name(await _next_frame(stream)) == 'connected'

    with pytest.raises(StopAsyncIteration):
        await _next_frame(stream)
    assert event_hub.subscription_count == 0


async def test_a_client_that_stops_reading_releases_the_stream(
    event_hub: UserEventHub,
) -> None:
    subscription = event_hub.subscribe(ALICE)
    stream = user_event_stream(
        subscription, authorize=_always_authorized, hub=event_hub, timing=QUIET
    )
    assert _frame_name(await _next_frame(stream)) == 'connected'

    await stream.aclose()

    assert event_hub.subscription_count == 0


async def test_a_stopping_hub_ends_the_streams_it_serves(event_hub: UserEventHub) -> None:
    """A shutdown ends an open stream, even one holding an event the client has not read yet."""
    subscription = event_hub.subscribe(ALICE)
    stream = user_event_stream(
        subscription, authorize=_always_authorized, hub=event_hub, timing=QUIET
    )
    assert _frame_name(await _next_frame(stream)) == 'connected'
    event_hub.deliver_payload(json.dumps({'user_id': ALICE, 'reason': REASON_NODE_HEARTBEAT}))

    await event_hub.stop()

    with pytest.raises(StopAsyncIteration):
        await _next_frame(stream)
    assert event_hub.subscription_count == 0


async def test_a_stopped_hub_refuses_new_streams(event_hub: UserEventHub) -> None:
    """A process that has stopped listening must say so instead of accepting a silent stream."""
    await event_hub.stop()

    with pytest.raises(EventStreamsStoppedError):
        event_hub.subscribe(ALICE)


# ── the route ─────────────────────────────────────────────────────────────────


async def test_the_events_route_404s_an_unknown_token(
    client: AsyncClient, event_hub: UserEventHub
) -> None:
    assert (await client.get('/pub/u/nobody/events')).status_code == HTTPStatus.NOT_FOUND
    assert event_hub.subscription_count == 0, 'a rejected stream must not subscribe anybody'


async def test_the_events_route_streams_uncacheable_headers_and_the_opening_frame(
    db: AsyncSession, event_hub: UserEventHub
) -> None:
    db.add(User(id=ALICE, name='alice', public_token=ALICE_TOKEN))
    await db.commit()

    response = await pub_user_events(ALICE_TOKEN, _ConnectedClient(), _session_factory())

    assert response.status_code == HTTPStatus.OK
    assert response.headers['content-type'].startswith('text/event-stream')
    assert 'no-store' in response.headers['cache-control']
    # A buffering proxy would hold the stream silent until its buffer filled up.
    assert response.headers['x-accel-buffering'] == 'no'

    frame = await _next_frame(response.body_iterator)
    assert _frame_name(frame) == 'connected'
    await _close_body(response)
    assert event_hub.subscription_count == 0


async def test_the_events_route_authorizes_the_same_token_or_id_rule_as_the_page(
    client: AsyncClient, db: AsyncSession, event_hub: UserEventHub
) -> None:
    db.add(User(id=ALICE, name='alice', public_token=ALICE_TOKEN))
    await db.commit()

    for accepted in (ALICE_TOKEN, ALICE):
        assert (await client.get(f'/pub/u/{accepted}/info')).status_code == HTTPStatus.OK
        # The stream is opened by calling the route: through the ASGI test transport an endless
        # response would have to be buffered whole before the client could see it.
        response = await pub_user_events(accepted, _ConnectedClient(), _session_factory())
        assert response.media_type == 'text/event-stream'
        assert _frame_name(await _next_frame(response.body_iterator)) == 'connected'
        await _close_body(response)

    assert event_hub.subscription_count == 0


async def test_a_stream_that_never_started_still_releases_its_subscription(
    db: AsyncSession, event_hub: UserEventHub
) -> None:
    """Cleanup cannot depend on the generator having run: the client may be gone before frame 1."""
    db.add(User(id=ALICE, name='alice', public_token=ALICE_TOKEN))
    await db.commit()

    response = await pub_user_events(ALICE_TOKEN, _ConnectedClient(), _session_factory())
    assert event_hub.subscription_count == 1

    assert response.background is not None
    await response.background()

    assert event_hub.subscription_count == 0


async def test_the_events_route_answers_503_when_the_process_is_at_its_cap(
    db: AsyncSession,
) -> None:
    hub = UserEventHub(None, max_subscriptions=1)
    hub.subscribe(BOB)
    configure_hub(hub)
    try:
        db.add(User(id=ALICE, name='alice', public_token=ALICE_TOKEN))
        await db.commit()

        with pytest.raises(HTTPException) as caught:
            await pub_user_events(ALICE_TOKEN, _ConnectedClient(), _session_factory())
        assert caught.value.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    finally:
        configure_hub(None)


async def test_the_events_route_answers_503_when_the_hub_has_been_stopped(
    db: AsyncSession, event_hub: UserEventHub
) -> None:
    """A stopping process refuses the stream instead of handing out one it would never notify."""
    db.add(User(id=ALICE, name='alice', public_token=ALICE_TOKEN))
    await db.commit()
    await event_hub.stop()

    with pytest.raises(HTTPException) as caught:
        await pub_user_events(ALICE_TOKEN, _ConnectedClient(), _session_factory())

    assert caught.value.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert event_hub.subscription_count == 0


# ── the change paths that notify ───────────────────────────────────────────────


@pytest.fixture()
async def seeded_pair(db: AsyncSession) -> tuple[Node, User, User]:
    """One node, two owners, one device and one pending peer each."""
    node = Node(id='node-1', name='node-1', url='http://agent:8000', token='node-token')  # noqa: S106
    alice = User(
        id=ALICE,
        name='alice',
        public_token=ALICE_TOKEN,
        public_key='alice-public',
        private_key='alice-private',
        vpn_ip='10.8.0.2',
    )
    bob = User(
        id=BOB,
        name='bob',
        public_token='tok-bob',  # noqa: S106 - a public URL segment, not a credential
        public_key='bob-public',
        private_key='bob-private',
        vpn_ip='10.8.0.3',
    )
    alice_device = Device(
        id=f'{ALICE}-device-Default',
        user_id=ALICE,
        name='Default',
        public_key=alice.public_key,
        private_key=alice.private_key,
        vpn_ip=alice.vpn_ip,
        is_legacy_default=True,
    )
    bob_device = Device(
        id=f'{BOB}-device-Default',
        user_id=BOB,
        name='Default',
        public_key=bob.public_key,
        private_key=bob.private_key,
        vpn_ip=bob.vpn_ip,
    )
    db.add_all(
        [
            node,
            alice,
            bob,
            alice_device,
            bob_device,
            Peer(
                id='peer-a',
                node_id=node.id,
                user_id=ALICE,
                device_id=alice_device.id,
                status='pending',
                psk_key='psk-a',
            ),
            Peer(
                id='peer-b',
                node_id=node.id,
                user_id=BOB,
                device_id=bob_device.id,
                status='pending',
                psk_key='psk-b',
            ),
        ]
    )
    await db.commit()
    return node, alice, bob


async def test_adding_a_device_notifies_its_owner_once_the_row_committed(
    client: AsyncClient, db: AsyncSession, event_hub: UserEventHub
) -> None:
    db.add(User(id=ALICE, name='alice', public_token=ALICE_TOKEN))
    await db.commit()
    alice = event_hub.subscribe(ALICE)

    response = await client.post(f'/pub/u/{ALICE_TOKEN}/devices', json={'name': 'laptop'})

    assert response.status_code == HTTPStatus.CREATED
    assert await _drain(alice) == [REASON_DEVICE_CREATED]


async def test_adding_a_device_notifies_nobody_else(
    client: AsyncClient, db: AsyncSession, event_hub: UserEventHub
) -> None:
    db.add_all(
        [
            User(id=ALICE, name='alice', public_token=ALICE_TOKEN),
            User(id=BOB, name='bob', public_token='tok-bob'),  # noqa: S106 - public URL segment
        ]
    )
    await db.commit()
    bob = event_hub.subscribe(BOB)

    assert (await client.post(f'/pub/u/{ALICE_TOKEN}/devices', json={'name': 'x'})).status_code == (
        HTTPStatus.CREATED
    )

    assert await _drain(bob) == []


async def test_a_device_add_that_never_commits_notifies_nobody(
    db: AsyncSession, event_hub: UserEventHub, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A request that dies before its commit must not announce anything, then or later."""
    db.add(User(id=ALICE, name='alice', public_token=ALICE_TOKEN))
    await db.commit()
    alice = event_hub.subscribe(ALICE)

    async def fail_before_commit(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError('broker publishing failed before the commit')

    monkeypatch.setattr(user_page_router, '_persist_and_publish_sync', fail_before_commit)

    with pytest.raises(RuntimeError):
        await pub_add_device(ALICE, DeviceCreate(name='laptop'), db)

    assert await _drain(alice) == [], 'the notification must not be delivered without a commit'

    # The notification was recorded on the aborted transaction; the rollback must discard it, so a
    # later commit of the same session cannot resurrect it.
    await db.rollback()
    await db.commit()
    assert await _drain(alice) == []


async def test_deleting_a_device_notifies_its_owner_once_the_tombstone_committed(
    client: AsyncClient, event_hub: UserEventHub, seeded_pair: Any
) -> None:
    _node, alice, _bob = seeded_pair
    subscription = event_hub.subscribe(ALICE)

    response = await client.delete(f'/pub/u/{ALICE_TOKEN}/devices/{alice.id}-device-Default')

    assert response.status_code == HTTPStatus.OK
    assert await _drain(subscription) == [REASON_DEVICE_DELETED]


async def test_a_sync_result_notifies_every_owner_it_acknowledged_and_no_one_else(
    client: AsyncClient,
    db: AsyncSession,
    event_hub: UserEventHub,
    worker_headers: dict[str, str],
    seeded_pair: Any,
) -> None:
    """One node becoming ready for one owner must not wait for the other owner's peer."""
    node, _alice, _bob = seeded_pair
    alice = event_hub.subscribe(ALICE)
    bob = event_hub.subscribe(BOB)

    response = await client.post(
        f'/internal/worker/nodes/{node.id}/sync-result',
        json={
            'ok': True,
            'peers': [
                {
                    'public_key': 'alice-public',
                    'status': 'active',
                    'rx_bytes': 4096,
                    'tx_bytes': 1024,
                }
            ],
        },
        headers=worker_headers,
    )

    assert response.status_code == HTTPStatus.OK
    assert await _drain(alice) == [REASON_NODE_SYNC]
    assert await _drain(bob) == []

    stored = (await db.execute(select(Peer).where(Peer.id == 'peer-a'))).scalar_one()
    assert stored.status == 'active'


async def test_a_sync_result_for_an_unknown_key_notifies_nobody(
    client: AsyncClient,
    event_hub: UserEventHub,
    worker_headers: dict[str, str],
    seeded_pair: Any,
) -> None:
    node, _alice, _bob = seeded_pair
    alice = event_hub.subscribe(ALICE)

    response = await client.post(
        f'/internal/worker/nodes/{node.id}/sync-result',
        json={'ok': True, 'peers': [{'public_key': 'someone-else', 'status': 'active'}]},
        headers=worker_headers,
    )

    assert response.status_code == HTTPStatus.OK
    assert await _drain(alice) == []


async def test_a_failed_sync_result_notifies_the_owners_on_that_node(
    client: AsyncClient,
    db: AsyncSession,
    event_hub: UserEventHub,
    worker_headers: dict[str, str],
    seeded_pair: Any,
) -> None:
    """A failed sync flips the node's diagnostic to ``error``, which the page renders.

    The peer keeps whatever readiness it already had - an acknowledged config stays downloadable -
    so this is a diagnostic change, but a page showing that node must re-read it. Both owners hold a
    peer on this node, so both are notified, once, inside the transaction.
    """
    node, _alice, _bob = seeded_pair
    alice = event_hub.subscribe(ALICE)
    bob = event_hub.subscribe(BOB)

    response = await client.post(
        f'/internal/worker/nodes/{node.id}/sync-result',
        json={'ok': False, 'error': 'agent unreachable'},
        headers=worker_headers,
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json() == {'status': 'failed'}
    assert await _drain(alice) == [REASON_NODE_SYNC]
    assert await _drain(bob) == [REASON_NODE_SYNC]

    stored = await db.get(Node, node.id)
    assert stored is not None
    await db.refresh(stored)
    assert stored.sync_status == 'failed'
    assert stored.sync_error == 'agent unreachable'
    # the diagnostic-only path must not touch peer state
    peer = (await db.execute(select(Peer).where(Peer.id == 'peer-a'))).scalar_one()
    await db.refresh(peer)
    assert peer.status == 'pending'


async def test_a_failed_sync_result_that_cannot_persist_notifies_nobody(
    client: AsyncClient,
    event_hub: UserEventHub,
    worker_headers: dict[str, str],
    seeded_pair: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The failure notification is transactional like every other one: no commit, no event.

    The call site is forced to fail *after* asking to notify, which is exactly the crash the
    transactional transport exists for - the announce and the write must share one fate.
    """
    node, _alice, _bob = seeded_pair
    alice = event_hub.subscribe(ALICE)

    original_status = node.sync_status
    original_error = node.sync_error

    async def _fail(*args: Any, **kwargs: Any) -> None:
        await notify_user_changes(*args, **kwargs)
        raise RuntimeError('failed after recording notification, before commit')

    monkeypatch.setattr('app.routers.internal_worker_parts.nodes.notify_user_changes', _fail)

    with pytest.raises(RuntimeError, match='failed after recording notification'):
        await client.post(
            f'/internal/worker/nodes/{node.id}/sync-result',
            json={'ok': False, 'error': 'agent unreachable'},
            headers=worker_headers,
        )

    assert await _drain(alice) == []
    async with _session_factory()() as session:
        stored = await session.get(Node, node.id)
        assert stored is not None
        assert stored.sync_status == original_status
        assert stored.sync_error == original_error


async def test_a_heartbeat_notifies_the_owners_whose_traffic_it_changed(
    client: AsyncClient,
    event_hub: UserEventHub,
    worker_headers: dict[str, str],
    seeded_pair: Any,
) -> None:
    node, _alice, _bob = seeded_pair
    alice = event_hub.subscribe(ALICE)
    bob = event_hub.subscribe(BOB)

    response = await client.post(
        f'/internal/worker/nodes/{node.id}/heartbeat-result',
        json={
            'ok': True,
            'peers': [
                {
                    'public_key': 'alice-public',
                    'status': 'active',
                    'rx_bytes': 2048,
                    'tx_bytes': 512,
                }
            ],
        },
        headers=worker_headers,
    )

    assert response.status_code == HTTPStatus.OK
    assert await _drain(alice) == [REASON_NODE_HEARTBEAT]
    assert await _drain(bob) == []
