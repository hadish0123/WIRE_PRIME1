from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from app.models import AsyncOperation, Node
from app.routers.internal_worker_parts.common import DB
from app.schemas.worker import HeartbeatResult, ProvisionResult, SyncResult
from app.services.devices import release_device_ips
from app.services.events import REASON_NODE_HEARTBEAT, REASON_NODE_SYNC, notify_user_changes
from app.services.local_lifecycle import enforce_local_lifecycle_for_user
from app.services.node_config import node_snapshot
from app.services.node_sync import apply_interface_result, apply_peer_result, load_node_with_peers
from app.services.operations import new_operation
from app.services.remnawave_sync import (
    enforce_remnawave_combined_limit_for_user,
    enqueue_remnawave_disable_users,
    enqueue_sync_nodes,
    now as utc_now,
    purge_confirmed_remnawave_deletes,
)

router = APIRouter()

ACTIVE_OPERATION_STATUSES = {'queued', 'pending', 'running'}
HEARTBEAT_TIMESTAMP_WRITE_INTERVAL = timedelta(seconds=60)


async def _apply_peer_results(
    db: DB,
    peers: list[Any],
    peer_results: list[Any],
    sampled_at: datetime,
) -> set[str]:
    """Apply a node's peer results and return the owners whose peers this result acknowledged.

    The returned ids are the owners a caller must notify: a result that acknowledged *any* peer is
    an acknowledgement for that owner, partial or not - the page's readiness is per device and per
    node, so there is no global "all nodes done" event to wait for.
    """
    # Peers are keyed by their device's public key: one owner may have several devices on the node.
    peers_by_public_key = {
        peer.device.public_key: peer for peer in peers if peer.device and peer.device.public_key
    }
    limited_node_ids: set[str] = set()
    local_lifecycle_node_ids: set[str] = set()
    remote_disable_uuids: set[str] = set()
    acknowledged_owner_ids: set[str] = set()
    for peer_result in peer_results:
        peer = peers_by_public_key.get(peer_result.public_key)
        if not peer:
            continue
        acknowledged_owner_ids.add(peer.user_id)
        sample = await apply_peer_result(db, peer, peer_result, sampled_at)
        if sample is not None:
            local_lifecycle_node_ids.update(
                await enforce_local_lifecycle_for_user(db, peer.user_id)
            )
            node_ids, user_uuids = await enforce_remnawave_combined_limit_for_user(db, peer.user_id)
            limited_node_ids.update(node_ids)
            remote_disable_uuids.update(user_uuids)
    await enqueue_sync_nodes(db, local_lifecycle_node_ids)
    await enqueue_sync_nodes(db, limited_node_ids)
    await enqueue_remnawave_disable_users(db, remote_disable_uuids)
    return acknowledged_owner_ids


def _aware(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def _heartbeat_timestamp_due(node: Node, observed_at: datetime) -> bool:
    if node.last_heartbeat_at is None:
        return True
    return observed_at - _aware(node.last_heartbeat_at) >= HEARTBEAT_TIMESTAMP_WRITE_INTERVAL


def _apply_node_heartbeat_result(node: Node, data: HeartbeatResult, observed_at: datetime) -> None:
    reachability_status = 'reachable' if data.ok else 'unreachable'
    health_status = 'online' if data.ok else 'offline'
    error = None if data.ok else data.error or 'Worker heartbeat failed'

    status_changed = (
        node.reachability_status != reachability_status
        or node.health_status != health_status
        or node.last_heartbeat_error != error
    )
    timestamp_due = status_changed or _heartbeat_timestamp_due(node, observed_at)

    if timestamp_due:
        node.last_heartbeat_at = observed_at
        if data.ok:
            node.last_seen_at = observed_at
    if node.reachability_status != reachability_status:
        node.reachability_status = reachability_status
    if node.health_status != health_status:
        node.health_status = health_status
    if node.last_heartbeat_error != error:
        node.last_heartbeat_error = error


def _operation_payload(operation: AsyncOperation) -> dict[str, Any]:
    return {
        'id': operation.id,
        'kind': operation.kind,
        'target_type': operation.target_type,
        'target_id': operation.target_id,
        'status': operation.status,
        'attempts': operation.attempts,
        'updated_at': operation.updated_at.isoformat(),
    }


async def _latest_provision_operation(db: DB, node_id: str) -> AsyncOperation | None:
    return await db.scalar(
        select(AsyncOperation)
        .where(
            AsyncOperation.kind == 'provision_node',
            AsyncOperation.target_type == 'node',
            AsyncOperation.target_id == node_id,
        )
        .order_by(AsyncOperation.updated_at.desc())
        .limit(1)
    )


def _provision_retry_due(
    node: Node,
    latest_operation: AsyncOperation | None,
    *,
    pending_cutoff: datetime,
    failed_cutoff: datetime,
) -> bool:
    if latest_operation and latest_operation.status in ACTIVE_OPERATION_STATUSES:
        return False
    if latest_operation is None:
        return True
    updated_at = _aware(latest_operation.updated_at)
    if node.provision_status == 'pending':
        return updated_at <= pending_cutoff
    if node.provision_status == 'failed':
        return updated_at <= failed_cutoff
    return False


@router.get('/sync/snapshot')
async def sync_snapshot(db: DB):
    nodes = (await db.execute(select(Node))).scalars().all()
    snapshots = []
    for node in nodes:
        _, peers = await load_node_with_peers(db, node.id)
        snapshots.append(node_snapshot(node, peers))
    return {'nodes': snapshots}


@router.get('/nodes/{node_id}/sync-snapshot')
async def node_sync_snapshot(node_id: str, db: DB):
    node, peers = await load_node_with_peers(db, node_id)
    return node_snapshot(node, peers)


@router.get('/nodes/{node_id}/provision-snapshot')
async def node_provision_snapshot(node_id: str, db: DB):
    node, peers = await load_node_with_peers(db, node_id)
    return node_snapshot(node, peers)


@router.post('/nodes/provision-recovery')
async def node_provision_recovery(
    db: DB,
    pending_after_seconds: Annotated[int, Query(ge=0)] = 60,
    failed_after_seconds: Annotated[int, Query(ge=0)] = 300,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
):
    observed_at = utc_now()
    pending_cutoff = observed_at - timedelta(seconds=pending_after_seconds)
    failed_cutoff = observed_at - timedelta(seconds=failed_after_seconds)
    nodes = (
        (
            await db.execute(
                select(Node)
                .where(Node.provision_status.in_({'pending', 'failed'}))
                .order_by(Node.created_at)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    operations = []
    for node in nodes:
        latest_operation = await _latest_provision_operation(db, node.id)
        if not _provision_retry_due(
            node,
            latest_operation,
            pending_cutoff=pending_cutoff,
            failed_cutoff=failed_cutoff,
        ):
            continue
        operation = new_operation('provision_node', 'node', node.id)
        db.add(operation)
        operations.append(operation)
    await db.commit()
    return {'operations': [_operation_payload(operation) for operation in operations]}


@router.post('/nodes/{node_id}/sync-result')
async def node_sync_result(node_id: str, data: SyncResult, db: DB):
    node, peers = await load_node_with_peers(db, node_id, for_update=True)
    if not data.ok:
        node.sync_status = 'failed'
        node.sync_error = data.error or 'Worker sync failed'
        node.last_error = node.sync_error
        # A failed sync changes what the page renders: every node on it now reports ``error`` while
        # an already-acknowledged config stays downloadable (``peer_available`` ignores the node's
        # diagnostic state). The owners holding a peer on this node must re-read that, in the same
        # transaction as the status write. Only ids and the reason travel - never the error text.
        await notify_user_changes(db, {peer.user_id for peer in peers}, reason=REASON_NODE_SYNC)
        await db.commit()
        return {'status': 'failed'}
    synced_at = utc_now()
    node.sync_status = 'succeeded'
    node.sync_error = None
    node.last_error = None
    node.last_synced_at = synced_at
    if data.interface:
        apply_interface_result(node, data.interface)
    sampled_at = utc_now()
    seen_public_keys: set[str] = set()
    for peer_result in data.peers:
        seen_public_keys.add(peer_result.public_key)
    acknowledged_owner_ids = await _apply_peer_results(db, peers, data.peers, sampled_at)
    released_candidates: set[str] = set()
    for peer in peers:
        device_public_key = peer.device.public_key if peer.device else None
        if peer.status == 'pending_delete' and device_public_key not in seen_public_keys:
            peer.status = 'deleted'
            acknowledged_owner_ids.add(peer.user_id)
        if peer.status == 'deleted':
            released_candidates.add(peer.device_id)
    # A device whose every peer is now confirmed gone has nothing left on any node, so its address
    # goes back to the finite pool. Bounded to the devices this result just touched: the rows were
    # already locked above (owners, then devices, then peers), so no new lock order is introduced.
    await release_device_ips(db, released_candidates)
    await purge_confirmed_remnawave_deletes(db)
    # Announce the acknowledged peers inside this transaction: the notification is delivered by the
    # commit below, so a rollback or a crash cannot tell a page to re-read a result that was never
    # persisted. Whichever process handles this request, every process LISTENing is notified.
    await notify_user_changes(db, acknowledged_owner_ids, reason=REASON_NODE_SYNC)
    await db.commit()
    return {'status': 'ok'}


@router.post('/nodes/{node_id}/provision-result')
async def node_provision_result(node_id: str, data: ProvisionResult, db: DB):
    node = await db.get(Node, node_id)
    if not node:
        raise HTTPException(status_code=404, detail='Node not found')
    if data.ok:
        node.provision_status = 'succeeded'
        node.last_error = None
        if data.interface:
            apply_interface_result(node, data.interface)
    else:
        node.provision_status = 'failed'
        node.last_error = data.error or 'Worker provision failed'
    await db.commit()
    return {'status': node.provision_status}


@router.post('/nodes/{node_id}/heartbeat-result')
async def node_heartbeat_result(node_id: str, data: HeartbeatResult, db: DB):
    node, peers = await load_node_with_peers(db, node_id, for_update=True)
    observed_at = utc_now()
    _apply_node_heartbeat_result(node, data, observed_at)
    if data.ok and data.peers:
        touched_owner_ids = await _apply_peer_results(db, peers, data.peers, observed_at)
        # A heartbeat refreshes traffic counters, which the page shows. Announce it in the same
        # transaction as the counters and let the hub coalesce: consecutive heartbeats for one owner
        # collapse into a single event instead of one `/info` read per heartbeat.
        await notify_user_changes(db, touched_owner_ids, reason=REASON_NODE_HEARTBEAT)
    await db.commit()
    return {'status': node.reachability_status}
