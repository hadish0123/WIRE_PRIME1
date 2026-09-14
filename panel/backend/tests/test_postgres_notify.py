"""Transactional PostgreSQL notifications - the real transport, on a throwaway schema.

``pg_notify`` is what makes a notification mean "this was committed": PostgreSQL delivers it when
the transaction commits and drops it when the transaction rolls back. SQLite cannot show that, and
neither can it show that a notification published by one process reaches a stream held by another,
so these tests need a live server and are opt-in exactly like the lock-order suite:

- they run only when ``AMNEZIA_TEST_POSTGRES_URL`` names an explicit throwaway test database;
- the ambient ``DATABASE_URL`` is refused, and so is any database whose name does not contain
  ``test``;
- every test creates one randomly named schema (the only object it touches) and drops it again.

Example::

    AMNEZIA_TEST_POSTGRES_URL=postgresql+asyncpg://u:p@127.0.0.1:54329/amnezia_notify_test \\
        uv run pytest tests/test_postgres_notify.py -q
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import uuid
from collections.abc import AsyncGenerator, Callable
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.database import Base
from app.models import User
from app.services.events import (
    REASON_DEVICE_CREATED,
    REASON_DEVICE_DELETED,
    StreamTiming,
    UserEventHub,
    UserEventSubscription,
    asyncpg_dsn,
    notify_user_changes,
    user_event_stream,
)

# The opt-in guard is shared with the lock-order suite on purpose: one environment variable, one set
# of refusals, so neither suite can be pointed at a database the other would reject.
from tests.test_postgres_lock_ordering import (
    TEST_DATABASE_URL_ENV,
    _validate_test_database_url as validate_test_database_url,
)

ALICE = 'user-1'
BOB = 'user-2'

# Generous: a live server plus two LISTEN connections; a failure here means the transport is broken.
SETTLE_TIMEOUT = 10.0


@pytest.fixture()
def test_database_url() -> str:
    url = os.environ.get(TEST_DATABASE_URL_ENV)
    if not url:
        pytest.skip(f'{TEST_DATABASE_URL_ENV} is not set: PostgreSQL notify tests are opt-in')
    try:
        return validate_test_database_url(url, ambient=os.environ.get('DATABASE_URL'))
    except ValueError as exc:  # pragma: no cover - guard rail
        pytest.fail(str(exc))


@pytest.fixture()
async def pg_engine(test_database_url: str) -> AsyncGenerator[AsyncEngine]:
    """A throwaway PostgreSQL schema with the ORM schema created inside it."""
    schema = f'user_events_{uuid.uuid4().hex[:12]}'
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


async def _wait_for(predicate: Callable[[], bool], within: float = SETTLE_TIMEOUT) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + within
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.05)
    pytest.fail(f'condition was not met within {within}s')


async def _collect(subscription: UserEventSubscription, within: float) -> list[object]:
    items: list[object] = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + within
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            return items
        try:
            items.append(await asyncio.wait_for(subscription.queue.get(), remaining))
        except TimeoutError:
            return items


@contextlib.asynccontextmanager
async def _listening_hub(test_database_url: str) -> AsyncGenerator[UserEventHub]:
    """A started hub - one process's listener - on its own ``LISTEN`` connection."""
    dsn = asyncpg_dsn(test_database_url)
    assert dsn is not None
    hub = UserEventHub(dsn)
    await hub.start()
    try:
        await _wait_for(lambda: hub.available)
        yield hub
    finally:
        await hub.stop()
    assert hub.available is False


@pytest.fixture()
async def listening_hub(test_database_url: str) -> AsyncGenerator[UserEventHub]:
    async with _listening_hub(test_database_url) as hub:
        yield hub


async def _seed_owner(sessions: async_sessionmaker[AsyncSession], user_id: str) -> None:
    async with sessions() as session:
        session.add(User(id=user_id, name=f'{user_id}-name'))
        await session.commit()


async def test_the_commit_delivers_the_notification_and_nothing_earlier(
    pg_sessions: async_sessionmaker[AsyncSession], listening_hub: UserEventHub
) -> None:
    """The notification exists as a consequence of the commit, so it cannot precede it."""
    await _seed_owner(pg_sessions, ALICE)
    subscription = listening_hub.subscribe(ALICE)

    async with pg_sessions() as session:
        await notify_user_changes(session, [ALICE], reason=REASON_DEVICE_CREATED)

        # Still inside the open transaction: PostgreSQL has not told anyone yet, and it must not.
        assert await _collect(subscription, within=0.5) == []

        await session.commit()

    assert await _collect(subscription, within=SETTLE_TIMEOUT) == [REASON_DEVICE_CREATED]


async def test_the_rollback_drops_the_notification_entirely(
    pg_sessions: async_sessionmaker[AsyncSession], listening_hub: UserEventHub
) -> None:
    await _seed_owner(pg_sessions, ALICE)
    subscription = listening_hub.subscribe(ALICE)

    async with pg_sessions() as session:
        await notify_user_changes(session, [ALICE], reason=REASON_DEVICE_CREATED)
        await session.rollback()

    assert await _collect(subscription, within=1.0) == []


async def test_a_notification_published_for_one_account_reaches_only_that_account(
    pg_sessions: async_sessionmaker[AsyncSession], listening_hub: UserEventHub
) -> None:
    await _seed_owner(pg_sessions, ALICE)
    await _seed_owner(pg_sessions, BOB)
    alice = listening_hub.subscribe(ALICE)
    bob = listening_hub.subscribe(BOB)

    async with pg_sessions() as session:
        await notify_user_changes(session, [ALICE], reason=REASON_DEVICE_DELETED)
        await session.commit()

    assert await _collect(alice, within=SETTLE_TIMEOUT) == [REASON_DEVICE_DELETED]
    assert await _collect(bob, within=0.5) == []


async def test_a_second_process_receives_the_notification_through_the_database(
    test_database_url: str,
    pg_sessions: async_sessionmaker[AsyncSession],
    listening_hub: UserEventHub,
) -> None:
    """The hub that publishes is never the hub that delivers: PostgreSQL is the shared bus.

    ``listening_hub`` is a *second* process's listener - it has no subscription activity of its own
    and nothing is delivered to it in-process - so an event arriving there can only have travelled
    through ``LISTEN``/``NOTIFY``. That is what keeps the stream correct behind a load balancer with
    several backend processes.
    """
    await _seed_owner(pg_sessions, ALICE)
    other_process = listening_hub.subscribe(ALICE)

    publisher_dsn = asyncpg_dsn(test_database_url)
    assert publisher_dsn is not None
    async with _listening_hub(test_database_url) as publishing_process:
        assert publishing_process is not listening_hub
        local = publishing_process.subscribe(ALICE)

        async with pg_sessions() as session:
            await notify_user_changes(session, [ALICE], reason=REASON_DEVICE_CREATED)
            await session.commit()

        assert await _collect(local, within=SETTLE_TIMEOUT) == [REASON_DEVICE_CREATED]
        assert await _collect(other_process, within=SETTLE_TIMEOUT) == [REASON_DEVICE_CREATED]


async def test_a_hub_without_a_database_url_reports_itself_degraded() -> None:
    """Degradation is stated, not implied: without a DSN the hub never claims the listener."""
    hub = UserEventHub(None)
    await hub.start()

    assert hub.available is False
    await hub.stop()


async def test_an_open_stream_announces_the_real_transport_on_postgres(
    pg_sessions: async_sessionmaker[AsyncSession], listening_hub: UserEventHub
) -> None:
    """The opening frame tells the client whether the stream is worth trusting."""
    await _seed_owner(pg_sessions, ALICE)
    subscription = listening_hub.subscribe(ALICE)

    async def authorize() -> bool:
        return True

    stream = user_event_stream(
        subscription,
        authorize=authorize,
        hub=listening_hub,
        timing=StreamTiming(heartbeat_seconds=30.0),
    )
    frame = await asyncio.wait_for(stream.__anext__(), SETTLE_TIMEOUT)
    data = _frame_data(frame)

    assert data == {'user_id': ALICE, 'notifications': True}
    await stream.aclose()
    assert listening_hub.subscription_count == 0


def _frame_data(frame: bytes) -> dict[str, Any]:
    for line in frame.decode().splitlines():
        if line.startswith('data: '):
            return json.loads(line[len('data: ') :])
    return {}
