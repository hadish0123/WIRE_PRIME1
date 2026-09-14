"""Public per-user page: dashboard summary, devices and configuration downloads.

Ownership lives in ``app.services.devices``: a user owns devices, a device owns its keypair, VPN IP
and peers. This router only resolves *which* device a request is about - a device id from the URL
for the ``/devices/{device_id}/...`` routes, or the durable migration ``Default`` device for the
legacy routes - and then builds the answer from that device's own credentials and its peer on the
requested node.

Readiness is per device and per node: an active peer on the node, cached node metadata, usable
device credentials and an active account are all required before a config, QR code, chunk list or
``vpn_uri`` is served. Anything else is ``503`` (still being provisioned) and a blocked, expired or
traffic-limited account is ``403`` on every download. Deleting a device stays allowed for its owner
even when the account is blocked, because revoking access must not require a working account.

The per-node ``status`` is a *diagnostic* - ``error`` follows the node's own last failed sync, even
for a peer it never applied - while ``ready``/``vpn_uri`` follow availability alone: a peer the node
already acknowledged keeps serving on that same node after a later failed sync, because the peer,
the credentials and the cached node metadata are all still on record.
"""

import io
import logging
import unicodedata
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import (
    Device,
    LocalAmneziawgUserLifetimeTraffic,
    Node,
    Peer,
    TelegramProxySettings,
    User,
)
from app.mtproxy_secret_crypto import decrypt
from app.services.account_policy import AccountInactiveError, account_status
from app.services.devices import (
    LIVE_PEER_STATUSES,
    PENDING_CONFIG_DETAIL,
    DeviceIpPoolExhaustedError,
    DeviceLimitExceededError,
    aggregate_device_status,
    count_live_devices,
    create_device,
    delete_device,
    effective_device_limit,
    get_device_peer,
    get_legacy_default_device,
    list_live_devices,
    node_status,
    peer_available,
    peers_by_device,
)
from app.services.events import (
    REASON_DEVICE_CREATED,
    REASON_DEVICE_DELETED,
    notify_user_changes,
)
from app.services.node_config import (
    QRStyle,
    attachment_headers,
    build_awg_client_config,
    build_user_amnezia_config_json,
    build_user_amnezia_qr_chunks,
    build_user_amnezia_vpn_uri,
    make_amnezia_qr_svg,
    make_awg_qr_svg,
    make_qr_svg,
)
from app.services.operations import enqueue_operation, new_operation
from app.services.public_access import resolve_public_user
from app.services.remnawave_display import derive_remnawave_display
from app.services.telegram_proxy import build_proxy_links, select_primary_node_state

log = logging.getLogger(__name__)

router = APIRouter()
DB = Annotated[AsyncSession, Depends(get_db)]

MAX_DEVICE_NAME_LENGTH = 64


class PublicTelegramProxy(BaseModel):
    enabled: bool
    primary_node_name: str
    tg_url: str
    https_url: str
    status: str

    model_config = ConfigDict(frozen=True)


class DeviceCreate(BaseModel):
    name: str


def _public_status(user: User, local_total: int) -> dict:
    """The account's public ``{'code', 'reason'}``, exactly as provisioning judges it.

    Delegated so the page and :func:`app.services.account_policy.require_active_owner` can never
    drift: an account the page calls inactive is one device creation refuses and vice versa.
    """
    return account_status(user, local_total, user.remnawave_user)


async def _public_dashboard_summary(user: User, db: AsyncSession) -> dict:
    local_traffic = (
        await db.execute(
            select(LocalAmneziawgUserLifetimeTraffic).where(
                LocalAmneziawgUserLifetimeTraffic.user_id == user.id
            )
        )
    ).scalar_one_or_none()
    local_total = local_traffic.total_bytes if local_traffic else 0
    rw = user.remnawave_user
    remote_used = rw.traffic_used_bytes if rw else 0
    total_used = remote_used + local_total
    traffic_limit = rw.traffic_limit_bytes if rw and rw.traffic_limit_bytes > 0 else None
    if rw is None and user.traffic_limit_bytes > 0:
        traffic_limit = user.traffic_limit_bytes
    updated_at = None
    if rw and rw.last_synced_at:
        updated_at = rw.last_synced_at
    if local_traffic and (updated_at is None or local_traffic.updated_at > updated_at):
        updated_at = local_traffic.updated_at
    return {
        'status': _public_status(user, local_total),
        'subscription': {
            'managed': rw is not None,
            'expire_at': rw.expire_at if rw else user.expire_at,
            'last_synced_at': rw.last_synced_at if rw else None,
        },
        'traffic': {
            'used_bytes': total_used,
            'limit_bytes': traffic_limit,
            'local_used_bytes': local_total,
            'remote_used_bytes': remote_used,
            'updated_at': local_traffic.updated_at if local_traffic else None,
        },
        'updated_at': updated_at,
    }


async def _get_public_user(db: AsyncSession, token_or_id: str) -> User | None:
    """The public identity rule; see :func:`app.services.public_access.resolve_public_user`."""
    return await resolve_public_user(db, token_or_id)


async def _guard_active_account(db: AsyncSession, user: User) -> None:
    """Deny configuration access to blocked, expired and traffic-limited accounts.

    Applied to every download route - legacy aliases, device-specific ones, QR codes and chunk
    lists - so no route can be used as a way around the account state.
    """
    if user.is_blocked:
        raise HTTPException(status_code=403, detail='Account is blocked')
    summary = await _public_dashboard_summary(user, db)
    code = summary['status']['code']
    if code != 'active':
        raise HTTPException(status_code=403, detail=f'Account is {code}')


async def _public_telegram_proxy(db: AsyncSession) -> PublicTelegramProxy | None:
    settings = await TelegramProxySettings.get_settings(db)
    payload = None
    if settings.enabled and settings.secret_encrypted is not None:
        try:
            state = await select_primary_node_state(db, settings)
        except TypeError, ValueError:
            log.warning('Stored Telegram proxy state is not valid for public links', exc_info=True)
            state = None
        if state is not None and settings.primary_node_id is not None:
            public_host = state.public_host
            public_port = state.public_port
            secret = decrypt(settings.secret_encrypted)
            node = await db.get(Node, settings.primary_node_id)
            if public_host is not None and public_port is not None and secret is not None and node:
                links = build_proxy_links(public_host, public_port, secret, settings.tls_domain)
                payload = PublicTelegramProxy(
                    enabled=True,
                    primary_node_name=node.name,
                    tg_url=links.tg_url,
                    https_url=links.t_me_url,
                    status=state.status,
                )
    return payload


def _public_user_name(user: User) -> str:
    rw = user.remnawave_user
    if rw is None:
        return user.name

    display = derive_remnawave_display(rw.description, rw.telegram_id)
    return display.display_name or user.name


# ── devices: names, peers, readiness ───────────────────────────────────────────


def _normalize_device_name(raw: str) -> str:
    """A bounded, non-blank device name; Unicode is kept, control characters are not.

    Control/format/surrogate code points are rejected rather than stripped: they break filenames,
    logs and headers, and silently rewriting a name the user typed would be worse than refusing it.
    """
    name = unicodedata.normalize('NFC', raw).strip()
    if not name:
        raise HTTPException(status_code=422, detail='Device name must not be blank')
    if len(name) > MAX_DEVICE_NAME_LENGTH:
        raise HTTPException(
            status_code=422,
            detail=f'Device name must be at most {MAX_DEVICE_NAME_LENGTH} characters',
        )
    if any(unicodedata.category(char).startswith('C') for char in name):
        raise HTTPException(
            status_code=422, detail='Device name must not contain control characters'
        )
    return name


async def _peer_for_device(db: AsyncSession, device_id: str, node_id: str) -> Peer | None:
    """The device's peer on this node, via the shared ``(device_id, node_id)`` lookup."""
    return await get_device_peer(db, device_id, node_id)


async def _peers_by_device(db: AsyncSession, device_ids: list[str]) -> dict[str, dict[str, Peer]]:
    if not device_ids:
        return {}
    rows = (await db.execute(select(Peer).where(Peer.device_id.in_(device_ids)))).scalars().all()
    return peers_by_device(rows)


async def _build_vpn_uri(device: Device, node: Node, peer: Peer, description: str) -> str | None:
    try:
        return build_user_amnezia_vpn_uri(device, node, description, peer.psk_key or '')
    except Exception:
        log.warning(
            'Failed to build VPN URI for device %s on node %s', device.id, node.id, exc_info=True
        )
        return None


async def _device_nodes(
    device: Device,
    nodes: list[Node],
    peers: dict[str, Peer],
    *,
    authorized: bool,
    user_name: str,
) -> list[dict]:
    entries = []
    for node in nodes:
        peer = peers.get(node.id)
        status = node_status(node, device, peer)
        ready = peer_available(node, device, peer) and authorized
        vpn_uri = None
        if ready and peer is not None:
            description = f'{user_name} / {device.name} / {node.name}'
            vpn_uri = await _build_vpn_uri(device, node, peer, description)
        entries.append(
            {
                'id': node.id,
                'name': node.name,
                'status': status,
                'ready': ready,
                'vpn_uri': vpn_uri,
            }
        )
    return entries


def _device_status(node_entries: list[dict]) -> str:
    """Aggregate device state via the shared rule in ``app.services.devices``.

    The ``ready`` flag decides, not the diagnostic string: a node whose last sync failed is
    reported as ``error`` while still serving its acknowledged peer, and the device stays usable
    for its owner. Only when nothing is usable do the diagnostics decide the aggregate.
    """
    return aggregate_device_status(
        (entry['status'] for entry in node_entries),
        any_ready=any(entry['ready'] for entry in node_entries),
    )


def _device_summary(device: Device, node_entries: list[dict]) -> dict:
    return {
        'id': device.id,
        'name': device.name,
        'created_at': device.created_at,
        'status': _device_status(node_entries),
        'nodes': node_entries,
    }


# ── queueing ───────────────────────────────────────────────────────────────────


async def _persist_and_publish_sync(db: AsyncSession, node_ids: list[str]) -> None:
    """Persist tracked sync operations in the current transaction, then publish them.

    The device, its peers and these operation rows commit together *before* the first broker call,
    so a broker failure or a crash can lose the publish but never the intent: the pending peers
    stay, the public summary keeps reporting them as pending, and the periodic sync is the recovery
    path. The commit also releases the owner/device row locks before any network call happens.
    """
    operations = [new_operation('sync_node', 'node', node_id) for node_id in node_ids]
    if not operations:
        await db.commit()
        return
    db.add_all(operations)
    await db.commit()

    from app.routers import internal_worker

    for operation, node_id in zip(operations, node_ids, strict=True):
        await enqueue_operation(db, operation, internal_worker.enqueue_sync_node, node_id)


# ── downloads ──────────────────────────────────────────────────────────────────


def _make_vpn_qr_svg(
    device: Device, node: Node, description: str, psk_key: str = ''
) -> bytes | None:
    try:
        return make_amnezia_qr_svg(
            device,
            node,
            description,
            psk_key,
            style=QRStyle(error='l', scale=3, border=2, dark='#111827'),
        )
    except Exception:
        return None


def _awg_config_response(
    device: Device, node: Node, peer: Peer, filename: str
) -> StreamingResponse:
    cfg = build_awg_client_config(device, node, peer.psk_key or '')
    if cfg is None:
        raise HTTPException(status_code=503, detail=PENDING_CONFIG_DETAIL)
    return StreamingResponse(
        io.BytesIO(cfg.encode()),
        media_type='text/plain',
        headers=attachment_headers(filename),
    )


def _vpn_config_response(
    device: Device, node: Node, peer: Peer, description: str, filename: str
) -> StreamingResponse:
    json_bytes = build_user_amnezia_config_json(device, node, description, peer.psk_key or '')
    if json_bytes is None:
        raise HTTPException(status_code=503, detail=PENDING_CONFIG_DETAIL)
    return StreamingResponse(
        io.BytesIO(json_bytes),
        media_type='application/octet-stream',
        headers=attachment_headers(filename),
    )


def _awg_qr_response(device: Device, node: Node, peer: Peer) -> Response:
    svg = make_awg_qr_svg(
        device,
        node,
        peer.psk_key or '',
        style=QRStyle(error='m', scale=3, border=2, dark='#111827'),
    )
    if not svg:
        raise HTTPException(status_code=503, detail=PENDING_CONFIG_DETAIL)
    return Response(svg, media_type='image/svg+xml')


def _vpn_qr_response(device: Device, node: Node, peer: Peer, description: str) -> Response:
    svg = _make_vpn_qr_svg(device, node, description, peer.psk_key or '')
    if not svg:
        raise HTTPException(
            status_code=503, detail='Configuration not available or too large for QR'
        )
    return Response(svg, media_type='image/svg+xml')


def _vpn_chunks_response(device: Device, node: Node, peer: Peer, description: str) -> dict:
    chunks = build_user_amnezia_qr_chunks(device, node, description, peer.psk_key or '')
    if chunks is None:
        raise HTTPException(status_code=503, detail=PENDING_CONFIG_DETAIL)
    svgs = [
        make_qr_svg(chunk_data, QRStyle(error='l', scale=3, border=2, dark='#111827')).decode(
            'utf-8'
        )
        for chunk_data in chunks
    ]
    return {'chunks': svgs}


async def _resolve_device_download(
    db: AsyncSession, token_or_id: str, device_id: str, node_id: str
) -> tuple[User, Device, Node, Peer]:
    """Owner-scoped device download context.

    A device id that is unknown, tombstoned or owned by somebody else is a ``404`` for every
    caller: device ids are opaque and must never confirm another account's devices.
    """
    user = await _get_public_user(db, token_or_id)
    device = await db.get(Device, device_id)
    if not user or device is None or device.user_id != user.id or device.deleted_at is not None:
        raise HTTPException(status_code=404)
    node = await db.get(Node, node_id)
    if node is None:
        raise HTTPException(status_code=404)
    await _guard_active_account(db, user)
    peer = await _peer_for_device(db, device.id, node.id)
    if peer is None or not peer_available(node, device, peer):
        raise HTTPException(status_code=503, detail=PENDING_CONFIG_DETAIL)
    return user, device, node, peer


async def _resolve_legacy_download(
    db: AsyncSession, token_or_id: str, node_id: str
) -> tuple[User, Device, Node, Peer]:
    """Legacy route context, pinned to the durable migration ``Default`` device.

    Never falls back to another device: with the migration device missing or deleted the legacy
    route is ``404`` even when the account owns newer devices.
    """
    user = await _get_public_user(db, token_or_id)
    if not user:
        raise HTTPException(status_code=404)
    node = await db.get(Node, node_id)
    if node is None:
        raise HTTPException(status_code=404)
    device = await get_legacy_default_device(db, user.id)
    if device is None or device.deleted_at is not None:
        raise HTTPException(status_code=404)
    await _guard_active_account(db, user)
    peer = await _peer_for_device(db, device.id, node.id)
    if peer is None or not peer_available(node, device, peer):
        raise HTTPException(status_code=503, detail=PENDING_CONFIG_DETAIL)
    return user, device, node, peer


# ── routes ─────────────────────────────────────────────────────────────────────


@router.get('/pub/u/{user_id}/info')
async def pub_user_info(user_id: str, db: DB):
    user = await _get_public_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404)
    summary = await _public_dashboard_summary(user, db)
    telegram_proxy = await _public_telegram_proxy(db)
    user_name = _public_user_name(user)
    device_limit = await effective_device_limit(db, user.id)
    device_count = await count_live_devices(db, user.id)
    base = {
        'user_name': user_name,
        'blocked': user.is_blocked,
        'device_limit': device_limit or 0,
        'device_count': device_count,
        'telegram_proxy': telegram_proxy,
        **summary,
    }
    # The device list is the owner's own data, so it stays visible whatever the account state:
    # ``authorized`` only decides usability. For a blocked, expired or traffic-limited account
    # every ``ready`` flag is off and every ``vpn_uri`` is null, so the list exposes no
    # configuration - but the owner still recognises the devices it owns and can revoke them.
    authorized = summary['status']['code'] == 'active'
    nodes = list((await db.execute(select(Node).order_by(Node.name, Node.id))).scalars().all())
    devices = await list_live_devices(db, user.id)
    peers_by_device = await _peers_by_device(db, [device.id for device in devices])

    devices_data = []
    for device in devices:
        entries = await _device_nodes(
            device,
            nodes,
            peers_by_device.get(device.id, {}),
            authorized=authorized,
            user_name=user_name,
        )
        devices_data.append(_device_summary(device, entries))

    # Legacy ``nodes`` are the pre-device-list field, not the owner's own list, and stay scoped to
    # the migration device's live peers only. A blocked account keeps its historical empty answer.
    nodes_data = []
    if not user.is_blocked:
        legacy_device = await get_legacy_default_device(db, user.id)
        if legacy_device is not None and legacy_device.deleted_at is None:
            legacy_peers = peers_by_device.get(legacy_device.id, {})
            for node in nodes:
                peer = legacy_peers.get(node.id)
                if peer is None or peer.status not in LIVE_PEER_STATUSES:
                    continue
                status = node_status(node, legacy_device, peer)
                ready = peer_available(node, legacy_device, peer) and authorized
                vpn_uri = None
                if ready:
                    vpn_uri = await _build_vpn_uri(
                        legacy_device, node, peer, f'{user_name} / {node.name}'
                    )
                nodes_data.append(
                    {
                        'id': node.id,
                        'name': node.name,
                        'status': status,
                        'ready': ready,
                        'vpn_uri': vpn_uri,
                    }
                )

    can_add_device = authorized and (device_limit is None or device_count < device_limit)
    return {
        **base,
        'nodes': nodes_data,
        'devices': devices_data,
        'can_add_device': can_add_device,
    }


@router.post('/pub/u/{user_id}/devices', status_code=201)
async def pub_add_device(user_id: str, payload: DeviceCreate, db: DB):
    """Create a named device, queue its provisioning and report it while it is pending."""
    user = await _get_public_user(db, user_id)
    if not user:
        raise HTTPException(status_code=404)
    name = _normalize_device_name(payload.name)
    await _guard_active_account(db, user)

    try:
        device, node_ids = await create_device(db, user.id, name=name)
    except AccountInactiveError as exc:
        # The account turned inactive between the guard above and the owner row lock: the same
        # answer as the guard, on freshly read state.
        raise HTTPException(status_code=403, detail=f'Account is {exc.code}') from exc
    except DeviceLimitExceededError as exc:
        raise HTTPException(status_code=409, detail=f'Device limit {exc.limit} reached') from exc
    except DeviceIpPoolExhaustedError as exc:
        # The finite subnet has nothing free right now: every address is held by a live device or by
        # a deleted device whose node has not confirmed the removal yet. That is a capacity state of
        # the deployment, so it is a 503 with the reason - not a 500 and not a client error.
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    nodes = list((await db.execute(select(Node).order_by(Node.name, Node.id))).scalars().all())
    peers = await _peers_by_device(db, [device.id])
    # Announce the new device in the same transaction as the device and its peers, so the owner's
    # open stream is notified only once the row exists.
    await notify_user_changes(db, [user.id], reason=REASON_DEVICE_CREATED)
    # Persist device + peers + sync intent in one transaction, then publish.
    await _persist_and_publish_sync(db, sorted(node_ids))

    entries = await _device_nodes(
        device,
        nodes,
        peers.get(device.id, {}),
        authorized=True,
        user_name=_public_user_name(user),
    )
    return _device_summary(device, entries)


@router.delete('/pub/u/{user_id}/devices/{device_id}')
async def pub_delete_device(user_id: str, device_id: str, db: DB):
    """Tombstone an own device: the limit slot frees at once, node removal is queued.

    Deliberately available to blocked, expired and limited accounts: revoking access to a device
    must not depend on the account being in good standing.
    """
    user = await _get_public_user(db, user_id)
    device = await db.get(Device, device_id)
    if not user or device is None or device.user_id != user.id:
        raise HTTPException(status_code=404)

    node_ids = await delete_device(db, device)
    # Same transaction as the tombstone: a rolled-back deletion notifies nobody.
    await notify_user_changes(db, [user.id], reason=REASON_DEVICE_DELETED)
    await _persist_and_publish_sync(db, sorted(node_ids))

    return {
        'id': device.id,
        'name': device.name,
        'status': 'deleting',
        'deleted_at': device.deleted_at,
        'device_count': await count_live_devices(db, user.id),
    }


@router.get('/pub/u/{user_id}/devices/{device_id}/config/awg/{node_id}')
async def pub_device_awg_config(user_id: str, device_id: str, node_id: str, db: DB):
    _, device, node, peer = await _resolve_device_download(db, user_id, device_id, node_id)
    return _awg_config_response(device, node, peer, f'{device.name}-{node.name}.conf')


@router.get('/pub/u/{user_id}/devices/{device_id}/config/vpn/{node_id}')
async def pub_device_vpn_config(user_id: str, device_id: str, node_id: str, db: DB):
    user, device, node, peer = await _resolve_device_download(db, user_id, device_id, node_id)
    description = f'{_public_user_name(user)} / {device.name} / {node.name}'
    return _vpn_config_response(device, node, peer, description, f'{device.name}-{node.name}.vpn')


@router.get('/pub/u/{user_id}/devices/{device_id}/qr/awg/{node_id}')
async def pub_device_awg_qr(user_id: str, device_id: str, node_id: str, db: DB):
    _, device, node, peer = await _resolve_device_download(db, user_id, device_id, node_id)
    return _awg_qr_response(device, node, peer)


@router.get('/pub/u/{user_id}/devices/{device_id}/qr/vpn/{node_id}')
async def pub_device_vpn_qr(user_id: str, device_id: str, node_id: str, db: DB):
    user, device, node, peer = await _resolve_device_download(db, user_id, device_id, node_id)
    description = f'{_public_user_name(user)} / {device.name} / {node.name}'
    return _vpn_qr_response(device, node, peer, description)


@router.get('/pub/u/{user_id}/devices/{device_id}/qr-chunks/vpn/{node_id}')
async def pub_device_vpn_qr_chunks(user_id: str, device_id: str, node_id: str, db: DB):
    """Returns all QR chunk SVGs for multi-part AmneziaVPN configs."""
    user, device, node, peer = await _resolve_device_download(db, user_id, device_id, node_id)
    description = f'{_public_user_name(user)} / {device.name} / {node.name}'
    return _vpn_chunks_response(device, node, peer, description)


@router.get('/pub/u/{user_id}/qr/awg/{node_id}')
async def pub_awg_qr(user_id: str, node_id: str, db: DB):
    _, device, node, peer = await _resolve_legacy_download(db, user_id, node_id)
    return _awg_qr_response(device, node, peer)


@router.get('/pub/u/{user_id}/qr/vpn/{node_id}')
async def pub_vpn_qr(user_id: str, node_id: str, db: DB):
    user, device, node, peer = await _resolve_legacy_download(db, user_id, node_id)
    return _vpn_qr_response(device, node, peer, f'{user.name} / {node.name}')


@router.get('/pub/u/{user_id}/qr-chunks/vpn/{node_id}')
async def pub_vpn_qr_chunks(user_id: str, node_id: str, db: DB):
    """Returns all QR chunk SVGs for multi-part AmneziaVPN configs."""
    user, device, node, peer = await _resolve_legacy_download(db, user_id, node_id)
    return _vpn_chunks_response(device, node, peer, f'{user.name} / {node.name}')


@router.get('/pub/u/{user_id}/config/awg/{node_id}')
async def pub_awg_config(user_id: str, node_id: str, db: DB):
    _, device, node, peer = await _resolve_legacy_download(db, user_id, node_id)
    return _awg_config_response(device, node, peer, f'{device.name}-{node.name}.conf')


@router.get('/pub/u/{user_id}/config/vpn/{node_id}')
async def pub_vpn_config(user_id: str, node_id: str, db: DB):
    user, device, node, peer = await _resolve_legacy_download(db, user_id, node_id)
    return _vpn_config_response(
        device, node, peer, f'{user.name} / {node.name}', f'{device.name}-{node.name}.vpn'
    )
