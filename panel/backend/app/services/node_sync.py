from datetime import datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import (
    Device,
    LocalAmneziawgTrafficDelta,
    LocalAmneziawgUserDailyTraffic,
    LocalAmneziawgUserLifetimeTraffic,
    LocalAmneziawgUserNodeDailyTraffic,
    LocalAmneziawgUserNodeLifetimeTraffic,
    Node,
    Peer,
    PeerEndpointSession,
    PeerTrafficSample,
    RemnawaveUser,
    User,
)
from app.schemas.worker import InterfaceResult, PeerSyncResult

# Lock order for every path that writes device ownership: owner (``users``) row, then device row,
# then peer rows, each class in ascending id order. Device deletion and creation
# (``app.services.devices``) already follow it, and a node result must too: it writes the owner's
# lifecycle/traffic state and peer rows whose locks it takes itself. Owner rows first means the two
# transactions serialize on the owner instead of waiting for each other's rows - which is what made
# a sync result and a device deletion deadlock on PostgreSQL.
MAX_LOCK_DISCOVERY_ATTEMPTS = 5


def _peers_of_node(node_id: str):
    return (
        select(Peer)
        .where(Peer.node_id == node_id)
        .options(selectinload(Peer.user), selectinload(Peer.device), selectinload(Peer.node))
    )


async def _pending_remnawave_purge_owner_ids(db: AsyncSession) -> set[str]:
    """Owners a sync result may delete at the end, so they are locked in the same ordered batch."""
    return set(
        (
            await db.execute(
                select(RemnawaveUser.user_id).where(RemnawaveUser.delete_requested_at.isnot(None))
            )
        ).scalars()
    )


async def _lock_owner_rows(db: AsyncSession, node_id: str) -> set[str]:
    """Lock, in ascending id order, every owner whose rows this transaction may write.

    The set is re-read until it stops growing because peers - and therefore owners - can be created
    while we wait for the locks. Only owner rows are locked here: an owner lock taken *after* a peer
    lock is the deadlock this order exists to prevent, so a peer whose owner we could not lock is
    skipped by :func:`load_node_with_peers` and handled by the next result instead.
    """
    locked: set[str] = set()
    for _ in range(MAX_LOCK_DISCOVERY_ATTEMPTS):
        owner_ids = set(
            (await db.execute(select(Peer.user_id).where(Peer.node_id == node_id))).scalars()
        )
        owner_ids |= await _pending_remnawave_purge_owner_ids(db)
        pending = sorted(owner_ids - locked)
        if not pending:
            break
        rows = (
            (
                await db.execute(
                    select(User)
                    .where(User.id.in_(pending))
                    .order_by(User.id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            )
            .scalars()
            .all()
        )
        locked.update(user.id for user in rows)
    return locked


async def _lock_peer_device_rows(db: AsyncSession, node_id: str) -> set[str]:
    """Lock the devices of the node's peers in ascending id order, after owners, before peers."""
    device_ids = set(
        (await db.execute(select(Peer.device_id).where(Peer.node_id == node_id))).scalars()
    )
    wanted = sorted(device_id for device_id in device_ids if device_id)
    if not wanted:
        return set()
    rows = (
        (
            await db.execute(
                select(Device)
                .where(Device.id.in_(wanted))
                .order_by(Device.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    return {device.id for device in rows}


async def load_node_with_peers(
    db: AsyncSession, node_id: str, *, for_update: bool = False
) -> tuple[Node, list[Peer]]:
    """Load a node with its peers, optionally with the result-path row locks.

    ``for_update=True`` is for the paths that also write peer status/traffic and owner lifecycle
    state. It locks in the order every device-ownership writer uses - owner rows, then device rows,
    then peer rows, each ordered by id - and refreshes what it locked, so rows read after waiting
    for a lock show the state the transaction that held it committed (device deletion sets
    ``device.deleted_at`` and ``peer.status = 'pending_delete'``). The status guard in
    :func:`apply_peer_result` stays the second line of defence. Node deletion also uses these locks
    before cascading peers and reclaiming device IPs. Read-only snapshots keep ``for_update=False``.
    """
    node = await db.get(Node, node_id)
    if not node:
        raise HTTPException(status_code=404, detail='Node not found')
    if not for_update:
        peers = (await db.execute(_peers_of_node(node.id))).scalars().all()
        return node, list(peers)

    owners = await _lock_owner_rows(db, node.id)
    devices = await _lock_peer_device_rows(db, node.id)
    peers = (
        (
            await db.execute(
                _peers_of_node(node.id).with_for_update().execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    # A peer created while we waited for the locks belongs to an owner or device we deliberately did
    # not lock (locking it now would take that lock while holding a peer lock). Skip it: the next
    # sync/heartbeat result owns it.
    return node, [peer for peer in peers if peer.user_id in owners and peer.device_id in devices]


# Peer statuses that mean "this peer is going away or gone". A node result may never move a peer
# back to a live status once it is here, otherwise a stale in-flight reply (or a heartbeat) would
# undo a device/user deletion.
TOMBSTONED_PEER_STATUSES = {'pending_delete', 'deleted'}


def apply_interface_result(node: Node, data: InterfaceResult) -> None:
    field_map = {
        'public_key': 'server_public_key',
        'endpoint': 'server_endpoint',
        'listen_port': 'listen_port',
        'jc': 'jc',
        'jmin': 'jmin',
        'jmax': 'jmax',
        's1': 's1',
        's2': 's2',
        's3': 's3',
        's4': 's4',
        'h1': 'h1',
        'h2': 'h2',
        'h3': 'h3',
        'h4': 'h4',
        'i1': 'i1',
        'i2': 'i2',
        'i3': 'i3',
        'i4': 'i4',
        'i5': 'i5',
        'mtu': 'mtu',
    }
    for source, target in field_map.items():
        value = getattr(data, source)
        if value is not None and getattr(node, target) != value:
            setattr(node, target, value)


async def apply_peer_result(
    db: AsyncSession, peer: Peer, data: PeerSyncResult, now: datetime
) -> PeerTrafficSample | None:
    # A tombstoned peer (device deleted, user blocked, peer being removed) never returns to a live
    # status because of a node reply: the reply may have been produced before the deletion
    # committed.
    stored_tombstone = peer.status in TOMBSTONED_PEER_STATUSES
    # The device tombstone is durable and authoritative. Checking it here means a stale peer status
    # cannot resurrect a deleted device's peer even if the row was read before the deletion landed.
    device_tombstone = peer.device is not None and peer.device.deleted_at is not None
    if device_tombstone and not stored_tombstone:
        peer.status = 'pending_delete'
    if (
        data.status in {'active', 'pending', 'pending_delete', 'deleted'}
        and peer.status != data.status
        and not (data.status in {'active', 'pending'} and (stored_tombstone or device_tombstone))
    ):
        peer.status = data.status
    if 'endpoint' in data.model_fields_set and peer.endpoint != data.endpoint:
        peer.endpoint = data.endpoint
    if data.last_handshake is not None and peer.last_handshake != data.last_handshake:
        peer.last_handshake = data.last_handshake
    await _apply_peer_endpoint_session(db, peer, data, now)
    if data.rx_bytes is None or data.tx_bytes is None:
        return None

    previous_rx = peer.raw_rx or 0
    previous_tx = peer.raw_tx or 0
    rx_reset_detected = peer.raw_rx is not None and data.rx_bytes < peer.raw_rx
    tx_reset_detected = peer.raw_tx is not None and data.tx_bytes < peer.raw_tx
    delta_rx = _counter_delta(peer.raw_rx, data.rx_bytes)
    delta_tx = _counter_delta(peer.raw_tx, data.tx_bytes)
    if peer.raw_rx != data.rx_bytes:
        peer.raw_rx = data.rx_bytes
    if peer.raw_tx != data.tx_bytes:
        peer.raw_tx = data.tx_bytes
    if delta_rx == 0 and delta_tx == 0:
        return None

    sample = PeerTrafficSample(
        peer_id=peer.id,
        sampled_at=now,
        rx_bytes=delta_rx,
        tx_bytes=delta_tx,
    )
    db.add(sample)
    db.add(
        LocalAmneziawgTrafficDelta(
            peer_id=peer.id,
            node_id=peer.node_id,
            user_id=peer.user_id,
            observed_at=now,
            previous_rx_bytes=previous_rx,
            previous_tx_bytes=previous_tx,
            current_rx_bytes=data.rx_bytes,
            current_tx_bytes=data.tx_bytes,
            rx_delta_bytes=delta_rx,
            tx_delta_bytes=delta_tx,
            total_delta_bytes=delta_rx + delta_tx,
            rx_reset_detected=rx_reset_detected,
            tx_reset_detected=tx_reset_detected,
        )
    )
    await _apply_local_traffic_aggregates(db, peer, now, delta_rx, delta_tx)
    return sample


async def _apply_peer_endpoint_session(
    db: AsyncSession, peer: Peer, data: PeerSyncResult, observed_at: datetime
) -> None:
    if not data.endpoint:
        return

    session = await db.scalar(
        select(PeerEndpointSession)
        .where(PeerEndpointSession.peer_id == peer.id)
        .order_by(PeerEndpointSession.last_seen_at.desc())
    )
    if session is None or session.endpoint != data.endpoint:
        db.add(
            PeerEndpointSession(
                peer_id=peer.id,
                node_id=peer.node_id,
                user_id=peer.user_id,
                endpoint=data.endpoint,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                last_handshake=data.last_handshake,
            )
        )
        return

    if data.last_handshake is not None and session.last_handshake != data.last_handshake:
        session.last_seen_at = observed_at
        session.last_handshake = data.last_handshake


def _counter_delta(previous: int | None, current: int) -> int:
    if previous is None:
        return 0
    if current < previous:
        return current
    return current - previous


async def _apply_local_traffic_aggregates(
    db: AsyncSession, peer: Peer, observed_at: datetime, rx_delta: int, tx_delta: int
) -> None:
    total_delta = rx_delta + tx_delta
    usage_day = observed_at.date()
    await _increase_aggregate(
        db,
        LocalAmneziawgUserDailyTraffic,
        {'user_id': peer.user_id, 'day': usage_day},
        (rx_delta, tx_delta, total_delta),
        observed_at,
    )
    await _increase_aggregate(
        db,
        LocalAmneziawgUserNodeDailyTraffic,
        {'user_id': peer.user_id, 'node_id': peer.node_id, 'day': usage_day},
        (rx_delta, tx_delta, total_delta),
        observed_at,
    )
    await _increase_aggregate(
        db,
        LocalAmneziawgUserLifetimeTraffic,
        {'user_id': peer.user_id},
        (rx_delta, tx_delta, total_delta),
        observed_at,
    )
    await _increase_aggregate(
        db,
        LocalAmneziawgUserNodeLifetimeTraffic,
        {'user_id': peer.user_id, 'node_id': peer.node_id},
        (rx_delta, tx_delta, total_delta),
        observed_at,
    )


async def _increase_aggregate(
    db: AsyncSession,
    model: type[Any],
    identity: dict[str, object],
    increment: tuple[int, int, int],
    observed_at: datetime,
) -> None:
    rx_delta, tx_delta, total_delta = increment
    statement = select(model)
    for column_name, value in identity.items():
        statement = statement.where(getattr(model, column_name) == value)

    aggregate = (await db.execute(statement)).scalar_one_or_none()
    if aggregate is None:
        aggregate = model(
            **identity,
            rx_bytes=rx_delta,
            tx_bytes=tx_delta,
            total_bytes=total_delta,
            updated_at=observed_at,
        )
        db.add(aggregate)
        return

    aggregate.rx_bytes += rx_delta
    aggregate.tx_bytes += tx_delta
    aggregate.total_bytes += total_delta
    aggregate.updated_at = observed_at
