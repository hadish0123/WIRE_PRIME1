"""Per-user change notifications behind the public page's event stream.

The public page never receives configuration bodies, keys or any other secret: a notification only
says "your authoritative state may have changed" and the client re-reads ``/pub/u/{token}/info``.
That keeps the transport replaceable and the rendered page always consistent with the database.

Delivery is *transactional*. A notification is recorded inside the transaction that writes the
change - ``pg_notify`` on PostgreSQL, which the server delivers when that transaction commits and
drops when it rolls back - so a client can never be told to re-read state that was never persisted.

Reliability across processes: every backend process runs one :class:`UserEventHub`, a single
PostgreSQL ``LISTEN`` connection that fans the notification out to the event streams that process is
serving. A notification published by whichever process handled a worker result therefore reaches a
stream held by any other process. The hub is bounded (one coalescing slot per user, a cap on open
streams), reconnects with backoff and ends the streams it serves when it stops; while it cannot
reach the listener its streams announce ``notifications: false`` and the client's periodic poll
stays the transport, so a degraded stream is never presented as reliable.

The in-process transport (:meth:`UserEventHub.deliver_local`, fed by the commit hook below) exists
for a backend that has no ``NOTIFY`` at all - the SQLite test database - and reaches only the
streams of its own process. It is a test transport, not a deployment mode: :func:`asyncpg_dsn`
accepts PostgreSQL URLs only, so a deployed process either has the listener or a stream that says
so.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator, Callable, Coroutine, Iterable
from dataclasses import dataclass, field
from typing import Any

import asyncpg
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

# The channel every process LISTENs on. The payload is the small JSON document built by
# :func:`_payloads` and never contains a key, config body or any other secret.
USER_EVENT_CHANNEL = 'amnezia_user_events'

# Reasons are descriptive only - the client always re-reads `/info` and never trusts this field.
REASON_DEVICE_CREATED = 'device.created'
REASON_DEVICE_DELETED = 'device.deleted'
REASON_NODE_SYNC = 'node.sync'
REASON_NODE_HEARTBEAT = 'node.heartbeat'
# Only heartbeat traffic is coalesced: it is the high-frequency, low-information reason and one
# re-read per window is enough for the traffic counters it refreshes. Every other reason - a device
# appearing or disappearing, a node becoming ready for an account - is delivered as soon as it
# commits, because a client waiting for it must not be held back by a heartbeat that landed first.
COALESCED_REASONS = frozenset({REASON_NODE_HEARTBEAT})

# Stream timing. The heartbeat keeps intermediaries from idling the connection out and lets the
# client notice a dead stream; the authorization recheck re-reads the token rule so a regenerated
# token or a deleted account stops an already-open stream.
HEARTBEAT_SECONDS = 20.0
AUTH_RECHECK_SECONDS = 60.0
# A hidden tab that becomes visible again revalidates on its own, so rechecking authorization more
# often than this would only add database reads to an idle page.
MIN_WAIT_SECONDS = 0.05
# Per-user coalescing window for :data:`COALESCED_REASONS`: a heartbeat that lands closer to the
# previous one than this produces a single trailing event instead of one `/info` read per heartbeat.
COALESCE_SECONDS = 2.0
# One coalescing slot per open stream; a second *unread* event is folded into the first.
STREAM_QUEUE_SIZE = 1
MAX_SUBSCRIPTIONS = 1000
RECONNECT_BACKOFF_SECONDS = (0.5, 1.0, 2.0, 5.0, 10.0)
# How often the listener notices that its connection went away.
LISTENER_POLL_SECONDS = 5.0
# How often an open stream checks whether its client is still there. The wait between frames is
# capped by this, otherwise a disconnect would only be noticed at the next heartbeat.
DISCONNECT_POLL_SECONDS = 5.0

_SESSION_INFO_KEY = 'user_event_payloads'
# The SAVEPOINTs a session currently has open, innermost last. Kept here so a notification can be
# tied to the transaction that holds it rather than to the session as a whole.
_SESSION_SAVEPOINTS_KEY = 'user_event_savepoints'


class SubscriptionLimitExceededError(RuntimeError):
    """Raised when one process already serves :data:`MAX_SUBSCRIPTIONS` open streams."""


class EventStreamsStoppedError(RuntimeError):
    """Raised when a stream is requested from a hub that has stopped serving them.

    A stopping process notifies nobody, so the client must fall back to its polling instead of
    holding a stream nothing will ever write to.
    """


def asyncpg_dsn(database_url: str | None) -> str | None:
    """The plain ``postgresql://`` DSN asyncpg needs, or ``None`` for any other backend.

    ``None`` means "this process has no listener": the streams it serves report
    ``notifications: false`` and rely on the client's polling instead of pretending otherwise.
    """
    if not database_url:
        return None
    if database_url.startswith('postgresql+asyncpg://'):
        return 'postgresql://' + database_url[len('postgresql+asyncpg://') :]
    if database_url.startswith(('postgresql://', 'postgres://')):
        return database_url
    return None


def _payloads(user_ids: Iterable[str], reason: str) -> list[str]:
    return [
        json.dumps({'user_id': user_id, 'reason': reason})
        for user_id in sorted({user_id for user_id in user_ids if user_id})
    ]


def _is_postgresql(session: AsyncSession) -> bool:
    return session.get_bind().dialect.name == 'postgresql'


async def notify_user_changes(
    session: AsyncSession, user_ids: Iterable[str], *, reason: str
) -> int:
    """Record a change notification for ``user_ids`` inside the session's current transaction.

    Must be called *before* the commit that persists the change, never after: on PostgreSQL the
    ``pg_notify`` runs in this transaction, so the notification is delivered by the commit and
    vanishes with a rollback - a rollback therefore reaches no client at all. Callers must not
    publish after committing or from a path that has not persisted the change yet.

    Returns the number of notifications recorded. On a backend without ``NOTIFY`` the payloads are
    parked on the session and handed to the in-process hub when the outermost transaction commits
    (see :func:`_flush_committed_payloads`), which keeps the commit coupling for the SQLite tests.
    """
    payloads = _payloads(user_ids, reason)
    if not payloads:
        return 0
    if _is_postgresql(session):
        for payload in payloads:
            await session.execute(
                text('SELECT pg_notify(:channel, :payload)'),
                {'channel': USER_EVENT_CHANNEL, 'payload': payload},
            )
        return len(payloads)
    # The level of the transaction that holds them: payloads recorded inside a SAVEPOINT must go
    # with it if it rolls back, while the transaction around it keeps its own.
    levels = session.info.setdefault(_SESSION_INFO_KEY, [])
    depth = _savepoint_depth(session)
    while len(levels) <= depth:
        levels.append([])
    levels[depth].extend(payloads)
    return len(payloads)


def _savepoint_depth(session: Session | AsyncSession) -> int:
    """How many SAVEPOINTs the session currently has open: the level a notification belongs to."""
    return len(session.info.get(_SESSION_SAVEPOINTS_KEY, ()))


def _rolled_back_savepoint_depth(session: Session, transaction: Any) -> int:
    """The level of the SAVEPOINT that rolled back, which is usually already forgotten by now.

    A savepoint's transaction ends - and is forgotten here - before the rollback event reaches this
    module, so its level is the number of savepoints still open plus the one that just went away.
    """
    savepoints = session.info.get(_SESSION_SAVEPOINTS_KEY, ())
    for index, tracked in enumerate(savepoints):
        if tracked is transaction:
            return index + 1
    return len(savepoints) + 1


@event.listens_for(Session, 'after_transaction_create')
def _track_savepoint(session: Session, transaction: Any) -> None:
    if getattr(transaction, 'nested', False):
        session.info.setdefault(_SESSION_SAVEPOINTS_KEY, []).append(transaction)


@event.listens_for(Session, 'after_transaction_end')
def _end_of_transaction(session: Session, transaction: Any) -> None:
    """Forget an open SAVEPOINT, and drop notifications no commit ever claimed.

    A transaction that ends with its payloads still parked did not commit them - the session was
    closed, or the outermost transaction went away some other way - so they must not survive into
    that session's next transaction. ``get_transaction()`` is ``None`` here only for that case: a
    SAVEPOINT release, and the internal subtransaction every flush commits, both end while the
    outermost transaction is still in place.
    """
    savepoints = session.info.get(_SESSION_SAVEPOINTS_KEY)
    if savepoints and savepoints[-1] is transaction:
        savepoints.pop()
    if not savepoints:
        session.info.pop(_SESSION_SAVEPOINTS_KEY, None)
    if session.get_transaction() is None:
        session.info.pop(_SESSION_INFO_KEY, None)


@event.listens_for(Session, 'after_commit')
def _flush_committed_payloads(session: Session) -> None:
    """Hand the notifications of a *committed* transaction to the in-process hub.

    Releasing a SAVEPOINT raises ``after_commit`` as well, and that is not the commit a client is
    waiting for: an outer rollback still discards the change. Only the outermost commit delivers, so
    :func:`notify_user_changes` can keep its guarantee - no client is told to re-read state that was
    never persisted.
    """
    if session.get_nested_transaction() is not None:
        return
    levels: list[list[str]] = session.info.pop(_SESSION_INFO_KEY, [])
    payloads = [payload for level in levels for payload in level]
    if payloads:
        get_hub().deliver_local(payloads)


@event.listens_for(Session, 'after_rollback')
def _drop_rolled_back_payloads(session: Session) -> None:
    """Drop the parked notifications of an outermost transaction that rolled back.

    A SAVEPOINT rollback raises this event too, and it is only that savepoint that is discarded
    then, so the payloads of the transaction around it stay parked until it ends itself.
    """
    if session.get_nested_transaction() is None:
        session.info.pop(_SESSION_INFO_KEY, None)
        session.info.pop(_SESSION_SAVEPOINTS_KEY, None)


@event.listens_for(Session, 'after_soft_rollback')
def _drop_rolled_back_savepoint_payloads(session: Session, previous_transaction: Any) -> None:
    """Drop exactly what the transaction that rolled back had recorded.

    A rolled-back SAVEPOINT takes its own level - and the levels of any savepoint nested inside it -
    with it and leaves the payloads of the transaction around it alone. Anything else that rolls
    back (the outermost transaction, or a flush's own subtransaction) takes every level with it.

    Dropping a notification the client never gets is safe - its periodic read reconciles the state -
    while delivering one for a change that was rolled back is not, which is why the ambiguous cases
    are resolved in favour of dropping.
    """
    if session.get_transaction() is None or not getattr(previous_transaction, 'nested', False):
        session.info.pop(_SESSION_INFO_KEY, None)
        return
    levels = session.info.get(_SESSION_INFO_KEY)
    if levels:
        del levels[_rolled_back_savepoint_depth(session, previous_transaction) :]


@dataclass(frozen=True)
class StreamTiming:
    """How often an open stream heartbeats, re-authorizes and checks for a gone client."""

    heartbeat_seconds: float = HEARTBEAT_SECONDS
    auth_recheck_seconds: float = AUTH_RECHECK_SECONDS
    disconnect_poll_seconds: float = DISCONNECT_POLL_SECONDS


# The timing a deployed stream runs with; tests pass their own instance.
DEFAULT_STREAM_TIMING = StreamTiming()


class _Terminated:
    """Sentinel that ends an open stream when the hub stops serving them."""

    __slots__ = ()


_TERMINATED = _Terminated()


@dataclass
class UserEventSubscription:
    """One open event stream: a bounded queue the hub writes a single coalescing slot into."""

    user_id: str
    queue: asyncio.Queue[object]

    def terminate(self) -> None:
        """End the stream now, whether or not it has an unread event it never got to yield."""
        with contextlib.suppress(asyncio.QueueEmpty):
            self.queue.get_nowait()
        with contextlib.suppress(asyncio.QueueFull):
            self.queue.put_nowait(_TERMINATED)


@dataclass
class _Fanout:
    """Everything one user has open in this process, plus its shared coalescing state."""

    subscriptions: list[UserEventSubscription] = field(default_factory=list)
    last_delivered_at: float = 0.0
    trailing: asyncio.TimerHandle | None = None


class UserEventHub:
    """One ``LISTEN`` connection per process, fanned out to that process's open streams.

    No client gets a database connection of its own: the single listening connection is shared, and
    delivery to a client is a non-blocking queue write. When the listener is down the hub reports
    :attr:`available` as ``False`` and keeps retrying with backoff - it never claims to deliver.
    """

    def __init__(
        self,
        dsn: str | None,
        *,
        coalesce_seconds: float = COALESCE_SECONDS,
        max_subscriptions: int = MAX_SUBSCRIPTIONS,
        reconnect_backoff: tuple[float, ...] = RECONNECT_BACKOFF_SECONDS,
        queue_size: int = STREAM_QUEUE_SIZE,
    ) -> None:
        self._dsn = dsn
        self._coalesce_seconds = coalesce_seconds
        self._max_subscriptions = max_subscriptions
        self._reconnect_backoff = reconnect_backoff
        self._queue_size = queue_size
        self._fanouts: dict[str, _Fanout] = {}
        self._available = False
        self._stopping = False
        self._task: asyncio.Task[None] | None = None
        self._connection: Any = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._disconnected = asyncio.Event()

    @property
    def available(self) -> bool:
        """Whether this process currently has the PostgreSQL listener."""
        return self._available

    @property
    def subscription_count(self) -> int:
        return sum(len(fanout.subscriptions) for fanout in self._fanouts.values())

    async def start(self) -> None:
        if self._dsn is None or self._task is not None:
            return
        self._loop = asyncio.get_running_loop()
        self._stopping = False
        self._disconnected.clear()
        self._task = asyncio.create_task(self._listen_forever())

    async def stop(self) -> None:
        """Stop listening and end every stream this process is still serving.

        A stream left open through a shutdown would be a client waiting on a channel that nothing
        will ever write to again, so each one is woken with the end sentinel instead of being left
        to its next heartbeat.
        """
        self._stopping = True
        self._disconnected.set()
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._available = False
        for fanout in self._fanouts.values():
            if fanout.trailing is not None:
                fanout.trailing.cancel()
            for subscription in fanout.subscriptions:
                subscription.terminate()
        self._fanouts.clear()

    def subscribe(self, user_id: str) -> UserEventSubscription:
        if self._stopping:
            raise EventStreamsStoppedError('The event hub is stopping')
        if self.subscription_count >= self._max_subscriptions:
            raise SubscriptionLimitExceededError(self._max_subscriptions)
        fanout = self._fanouts.setdefault(user_id, _Fanout())
        subscription = UserEventSubscription(
            user_id=user_id, queue=asyncio.Queue(maxsize=self._queue_size)
        )
        fanout.subscriptions.append(subscription)
        return subscription

    def unsubscribe(self, subscription: UserEventSubscription) -> None:
        """Release one stream and, with its user's last stream, that user's coalescing timer."""
        fanout = self._fanouts.get(subscription.user_id)
        if fanout is None:
            return
        if subscription in fanout.subscriptions:
            fanout.subscriptions.remove(subscription)
        if not fanout.subscriptions:
            if fanout.trailing is not None:
                fanout.trailing.cancel()
            self._fanouts.pop(subscription.user_id, None)

    def deliver_local(self, payloads: Iterable[str]) -> None:
        """Fan out notifications committed on a backend without ``NOTIFY``.

        Only reaches this process; see the module docstring.
        """
        for payload in payloads:
            self.deliver_payload(payload)

    def deliver_payload(self, payload: str) -> None:
        """Fan out one serialized notification; anything malformed is dropped, not guessed at."""
        try:
            data = json.loads(payload)
        except ValueError:
            log.warning('Discarding malformed user event payload')
            return
        if not isinstance(data, dict):
            return
        user_id = data.get('user_id')
        if not isinstance(user_id, str) or not user_id:
            return
        reason = data.get('reason')
        self._fan_out(user_id, reason if isinstance(reason, str) else '')

    def _resolve_loop(self) -> asyncio.AbstractEventLoop | None:
        """The loop that owns the subscriptions, resolved on first use when never started."""
        if self._loop is not None:
            return self._loop
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            log.warning('No running event loop to deliver user notifications on')
            return None
        return self._loop

    def _fan_out(self, user_id: str, reason: str) -> None:
        fanout = self._fanouts.get(user_id)
        if fanout is None:
            return
        loop = self._resolve_loop()
        if loop is None:
            return
        now = loop.time()
        elapsed = now - fanout.last_delivered_at
        if reason not in COALESCED_REASONS or elapsed >= self._coalesce_seconds:
            self._deliver(fanout, reason, loop)
            return
        # Inside the coalescing window: one trailing delivery is enough, because the client re-reads
        # the whole authoritative state and therefore also sees the change this event is standing in
        # for.
        if fanout.trailing is None or fanout.trailing.cancelled():
            fanout.trailing = loop.call_later(
                self._coalesce_seconds - elapsed, self._deliver, fanout, reason, loop
            )

    def _deliver(self, fanout: _Fanout, reason: str, loop: asyncio.AbstractEventLoop) -> None:
        # This delivery supersedes a trailing one: the client re-reads the whole authoritative
        # state, so a pending event has nothing left to announce - and keeping it would delay a
        # change that is already on its way for longer than the window it was booked in.
        if fanout.trailing is not None:
            fanout.trailing.cancel()
        fanout.trailing = None
        fanout.last_delivered_at = loop.time()
        for subscription in fanout.subscriptions:
            # Full queue means an unread event is already waiting; that event makes the client
            # re-read state that includes this one, so dropping it here loses nothing.
            with contextlib.suppress(asyncio.QueueFull):
                subscription.queue.put_nowait(reason)

    async def _listen_forever(self) -> None:
        attempt = 0
        while not self._stopping:
            connection = None
            try:
                connection = await asyncpg.connect(self._dsn)
                await connection.add_listener(USER_EVENT_CHANNEL, self._on_notification)
            except asyncio.CancelledError:
                # A connection that was opened but never attached would otherwise be leaked: closing
                # it is not part of the cancelled task's cleanup, so it happens here.
                await self._discard(connection)
                raise
            except Exception:
                self._available = False
                await self._discard(connection)
                delay = self._reconnect_backoff[min(attempt, len(self._reconnect_backoff) - 1)]
                attempt += 1
                log.warning(
                    'User event listener unavailable; event streams will report degraded',
                    exc_info=True,
                )
                await asyncio.sleep(delay)
                continue
            attempt = 0
            self._connection = connection
            self._available = True
            try:
                await self._wait_for_loss(connection)
            finally:
                self._available = False
                self._connection = None
                await self._discard(connection)
        self._available = False

    async def _discard(self, connection: Any) -> None:
        """Release a listener connection in whatever state it is, without raising.

        ``add_listener`` can fail on an already-open connection, and a shutdown can cut the close
        short; either way the socket must not be left behind.
        """
        if connection is None:
            return
        if not connection.is_closed():
            with contextlib.suppress(Exception):
                await connection.close()
        if not connection.is_closed():
            # A close that was cut short still has to release the socket: ``terminate`` drops the
            # transport at once instead of waiting for the protocol, and it never raises here.
            with contextlib.suppress(Exception):
                connection.terminate()

    async def _wait_for_loss(self, connection: asyncpg.Connection) -> None:
        """Block until the listener is stopped or its connection dies."""
        self._disconnected.clear()
        while not self._stopping and not connection.is_closed():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._disconnected.wait(), timeout=LISTENER_POLL_SECONDS)
            if self._disconnected.is_set():
                return

    def _on_notification(
        self, _connection: asyncpg.Connection, _pid: int, _channel: str, payload: str
    ) -> None:
        loop = self._loop
        if loop is None:
            return
        # asyncpg calls this from the connection's protocol; hop onto the loop explicitly so the
        # fan-out always runs in the loop that owns the subscriptions.
        loop.call_soon_threadsafe(self.deliver_payload, payload)


class _HubRegistry:
    """The process hub, kept in one place instead of a module-level rebinding."""

    hub: UserEventHub | None = None


_registry = _HubRegistry()


def get_hub() -> UserEventHub:
    """The process-wide hub, created on first use and started by the application lifespan."""
    if _registry.hub is None:
        from app.database import DATABASE_URL

        _registry.hub = UserEventHub(asyncpg_dsn(DATABASE_URL))
    return _registry.hub


def configure_hub(hub: UserEventHub | None) -> None:
    """Replace the process hub (tests) or drop it so the next call rebuilds it."""
    _registry.hub = hub


def _sse_frame(name: str, data: dict[str, Any]) -> bytes:
    return f'event: {name}\ndata: {json.dumps(data)}\n\n'.encode()


class _Timer:
    """Sentinel marking "the wait expired" as distinct from a real notification reason."""

    __slots__ = ()


_TIMER = _Timer()


async def _put_after(queue: asyncio.Queue[object], delay: float, item: object) -> None:
    await asyncio.sleep(delay)
    with contextlib.suppress(asyncio.QueueFull):
        queue.put_nowait(item)


async def user_event_stream(
    subscription: UserEventSubscription,
    *,
    authorize: Callable[[], Coroutine[Any, Any, bool]],
    hub: UserEventHub,
    is_disconnected: Callable[[], Coroutine[Any, Any, bool]] | None = None,
    timing: StreamTiming = DEFAULT_STREAM_TIMING,
) -> AsyncIterator[bytes]:
    """The public ``text/event-stream`` body: connected, changed, heartbeat, unauthorized.

    The stream holds no database session and no per-client connection - ``authorize`` opens a fresh,
    short session for each recheck - and it releases its subscription on every exit path, including
    client disconnect and application shutdown (the hub ends it with the termination sentinel).
    """
    loop = asyncio.get_running_loop()
    next_heartbeat = loop.time() + timing.heartbeat_seconds
    next_auth = loop.time() + timing.auth_recheck_seconds
    try:
        yield _sse_frame(
            'connected', {'user_id': subscription.user_id, 'notifications': hub.available}
        )
        while True:
            now = loop.time()
            wait = max(
                MIN_WAIT_SECONDS,
                min(next_heartbeat, next_auth, now + timing.disconnect_poll_seconds) - now,
            )
            ticker = loop.create_task(_put_after(subscription.queue, wait, _TIMER))
            try:
                item = await subscription.queue.get()
            finally:
                ticker.cancel()
            if item is _TERMINATED:
                # The hub stopped serving streams - the process is shutting down. Ending the stream
                # here is what the client's own reconnect and polling fallback expect; leaving it
                # open would present a channel that nothing will ever write to again.
                return
            if item is not _TIMER:
                yield _sse_frame('changed', {'reason': item})
            if is_disconnected is not None and await is_disconnected():
                return
            now = loop.time()
            if now >= next_auth:
                next_auth = now + timing.auth_recheck_seconds
                if not await authorize():
                    # The token was regenerated, the account removed: the client must stop
                    # reconnecting and fall back to its polling, which surfaces the same state.
                    yield _sse_frame('unauthorized', {'reason': 'token'})
                    return
            if now >= next_heartbeat:
                next_heartbeat = now + timing.heartbeat_seconds
                yield b': keepalive\n\n'
    finally:
        hub.unsubscribe(subscription)
