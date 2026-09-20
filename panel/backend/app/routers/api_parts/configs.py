"""Admin configuration downloads: device-scoped routes plus the legacy migration-``Default`` ones.

*Which* device a request is about is never guessed. The device-scoped routes take a device id from
the URL, and the legacy routes that predate devices resolve **only** the durable migration
``Default`` device (the ``is_legacy_default`` marker): a user without a live one gets ``409``
instead of another device's credentials. That is the whole contract of this module - an implicit
route may not become an implicit *choice* among devices.

Every config, QR code and archive is built from that device's own keypair, VPN IP and its peer's PSK
on the requested node. The retained per-user key columns are frozen migration metadata and are never
read here: there is no credential fallback. Readiness and the account gate are the shared rules from
``app.services.devices`` and ``app.services.account_policy``, so an admin download and a public
download of the same device cannot disagree: an unacknowledged peer is ``503``, and a blocked,
expired, traffic-limited or deleted account is ``403`` on every download route.
"""

import io

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Device, Node, Peer, User
from app.routers.api_parts.common import DB, guard_tenant_owner, owner_filter, node_filter, get_scoped_node
from app.services.account_policy import fresh_account_status
from app.services.devices import (
    PENDING_CONFIG_DETAIL,
    get_device_peer,
    get_legacy_default_device,
    node_metadata_cached,
    peer_available,
    peers_by_device,
)
from app.services.node_config import (
    ConfigZipEntry,
    QRStyle,
    attachment_headers,
    build_awg_client_config,
    build_configs_zip,
    build_user_amnezia_qr_chunks,
    config_entry_name,
    device_archive_folder,
    make_qr_svg,
)

router = APIRouter()

NO_DEFAULT_DEVICE_DETAIL = (
    'User has no migration Default device; request one device explicitly via '
    '/api/users/{user_id}/devices/{device_id}/configs'
)
NOTHING_READY_DETAIL = 'No device configuration is available yet'
# Public ``.conf``/``.vpn`` and the migration-compatible QR sizes stay exactly as they were.
_AWG_QR_STYLE = QRStyle(error='m', scale=4, border=2, dark='#000000')
_AMNEZIA_QR_STYLE = QRStyle(error='l', scale=4, border=2, dark='#000000')


async def _get_user_or_404(db: AsyncSession, user_id: str) -> User:
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    guard_tenant_owner(user.owner_admin_id)
    return user


async def _guard_active_account(db: AsyncSession, user_id: str) -> None:
    """Refuse configuration access for an inactive account, on freshly read state.

    Delegated to :mod:`app.services.account_policy` so the admin answer and the public page's answer
    are the same decision: only ``active`` downloads.
    """
    status = await fresh_account_status(db, user_id)
    if status['code'] != 'active':
        raise HTTPException(status_code=403, detail=f'Account is {status["code"]}')


async def _resolve_device(db: AsyncSession, user_id: str, device_id: str) -> Device:
    """The requested device of this owner; every other resolution is a plain ``404``.

    A device id that is unknown, tombstoned or owned by somebody else is indistinguishable by
    design, so one account cannot probe another's device ids.
    """
    device = await db.get(Device, device_id)
    if device is None or device.user_id != user_id or device.deleted_at is not None:
        raise HTTPException(status_code=404, detail='Device not found')
    return device


async def _resolve_legacy_device(db: AsyncSession, user_id: str) -> Device:
    """The migration ``Default`` device for an implicit (pre-device) route, or ``409``.

    Resolved through the durable marker, never through the display name, and never substituted by
    another device: with the migration device missing or deleted the legacy route refuses and the
    caller has to name a device explicitly.
    """
    device = await get_legacy_default_device(db, user_id)
    if device is None or device.deleted_at is not None:
        raise HTTPException(status_code=409, detail=NO_DEFAULT_DEVICE_DETAIL)
    return device


async def _get_node_or_404(db: AsyncSession, node_id: str) -> Node:
    return await get_scoped_node(node_id, db)


async def _config_entries(db: AsyncSession, device: Device, nodes: list[Node]) -> list[dict]:
    """Per-node config texts of one device, with the shared readiness rule applied per node.

    A node that is not ready reports *why* instead of a config: reporting a config for a peer the
    node has not acknowledged would hand out credentials for a tunnel that does not exist yet, and
    a pending peer's PSK is not the one the node has. The one exception is the historic reason text
    for missing node metadata, kept so an existing caller sees the same answer as before.
    """
    entries: list[dict] = []
    for node in nodes:
        peer = await get_device_peer(db, device.id, node.id)
        config = (
            build_awg_client_config(device, node, peer.psk_key or '')
            if peer is not None and peer_available(node, device, peer)
            else None
        )
        if config is not None:
            entries.append({'node_id': node.id, 'node_name': node.name, 'config': config})
            continue
        reason = (
            'node metadata not yet cached'
            if not node_metadata_cached(node)
            else PENDING_CONFIG_DETAIL
        )
        entries.append(
            {'node_id': node.id, 'node_name': node.name, 'config': None, 'reason': reason}
        )
    return entries


async def _peer_for_device(db: AsyncSession, device_id: str, node_id: str) -> Peer | None:
    """The device's peer on this node, via the shared ``(device_id, node_id)`` key."""
    return await get_device_peer(db, device_id, node_id)


async def _ready_peer(db: AsyncSession, device: Device, node: Node) -> Peer:
    peer = await _peer_for_device(db, device.id, node.id)
    if peer is None or not peer_available(node, device, peer):
        raise HTTPException(status_code=503, detail=PENDING_CONFIG_DETAIL)
    return peer


async def _nodes(db: AsyncSession) -> list[Node]:
    return list((await db.execute(select(Node).where(node_filter()).order_by(Node.name, Node.id))).scalars().all())


async def _ready_zip_entries(
    db: AsyncSession, devices: list[Device], *, folder_per_device: bool
) -> list[ConfigZipEntry]:
    """The archive plan for the given devices: only device/node pairs that are ready right now."""
    nodes = await _nodes(db)
    rows = (
        (
            await db.execute(
                select(Peer).where(Peer.device_id.in_([device.id for device in devices]))
            )
        )
        .scalars()
        .all()
    )
    grouped = peers_by_device(rows)
    entries: list[ConfigZipEntry] = []
    for device in devices:
        by_node = grouped.get(device.id, {})
        folder = device_archive_folder(device) if folder_per_device else None
        for node in nodes:
            peer = by_node.get(node.id)
            if peer is None or not peer_available(node, device, peer):
                continue
            entries.append(
                ConfigZipEntry(
                    device=device,
                    node=node,
                    peer=peer,
                    name=config_entry_name(device, node, folder=folder),
                )
            )
    return entries


async def _zip_response(
    db: AsyncSession, devices: list[Device], *, filename: str, folder_per_device: bool
) -> StreamingResponse:
    entries = await _ready_zip_entries(db, devices, folder_per_device=folder_per_device)
    if not entries:
        # A pending-only or unconfigured owner gets a diagnosable answer, not an empty archive.
        raise HTTPException(status_code=409, detail=NOTHING_READY_DETAIL)
    return StreamingResponse(
        build_configs_zip(entries),
        media_type='application/zip',
        headers=attachment_headers(filename),
    )


def _awg_config_response(device: Device, node: Node, peer: Peer) -> StreamingResponse:
    config = build_awg_client_config(device, node, peer.psk_key or '')
    if config is None:
        raise HTTPException(status_code=503, detail=PENDING_CONFIG_DETAIL)
    return StreamingResponse(
        io.BytesIO(config.encode()),
        media_type='text/plain',
        headers=attachment_headers(f'{device.name}-{node.name}.conf'),
    )


def _awg_qr_response(device: Device, node: Node, peer: Peer) -> Response:
    config = build_awg_client_config(device, node, peer.psk_key or '')
    if config is None:
        raise HTTPException(status_code=503, detail=PENDING_CONFIG_DETAIL)
    return Response(make_qr_svg(config, _AWG_QR_STYLE), media_type='image/svg+xml')


def _amnezia_qr_response(device: Device, node: Node, peer: Peer, description: str) -> Response:
    chunks = build_user_amnezia_qr_chunks(device, node, description, peer.psk_key or '')
    if chunks is None:
        raise HTTPException(status_code=503, detail=PENDING_CONFIG_DETAIL)
    if len(chunks) > 1:
        raise HTTPException(status_code=400, detail='Config too large for a single QR code')
    return Response(make_qr_svg(chunks[0], _AMNEZIA_QR_STYLE), media_type='image/svg+xml')


# ── device-scoped routes ───────────────────────────────────────────────────────


@router.get('/users/{user_id}/devices/{device_id}/configs')
async def api_device_configs(user_id: str, device_id: str, db: DB):
    """Per-node config texts for one device; unready nodes are reported, not omitted."""
    await _get_user_or_404(db, user_id)
    device = await _resolve_device(db, user_id, device_id)
    await _guard_active_account(db, user_id)
    return await _config_entries(db, device, await _nodes(db))


@router.get('/users/{user_id}/devices/{device_id}/configs/zip')
async def api_device_configs_zip(user_id: str, device_id: str, db: DB):
    """Archive of one device's ready configs, one entry per acknowledged node."""
    user = await _get_user_or_404(db, user_id)
    device = await _resolve_device(db, user_id, device_id)
    await _guard_active_account(db, user_id)
    return await _zip_response(
        db,
        [device],
        filename=f'{user.name}-{device.name}-configs.zip',
        folder_per_device=False,
    )


@router.get('/users/{user_id}/devices/{device_id}/configs/{node_id}')
async def api_device_config_for_node(user_id: str, device_id: str, node_id: str, db: DB):
    await _get_user_or_404(db, user_id)
    device = await _resolve_device(db, user_id, device_id)
    node = await _get_node_or_404(db, node_id)
    await _guard_active_account(db, user_id)
    return _awg_config_response(device, node, await _ready_peer(db, device, node))


@router.get('/users/{user_id}/devices/{device_id}/qr/{node_id}')
async def api_device_qr(user_id: str, device_id: str, node_id: str, db: DB):
    await _get_user_or_404(db, user_id)
    device = await _resolve_device(db, user_id, device_id)
    node = await _get_node_or_404(db, node_id)
    await _guard_active_account(db, user_id)
    return _awg_qr_response(device, node, await _ready_peer(db, device, node))


@router.get('/users/{user_id}/devices/{device_id}/qr-amnezia/{node_id}')
async def api_device_qr_amnezia(user_id: str, device_id: str, node_id: str, db: DB):
    user = await _get_user_or_404(db, user_id)
    device = await _resolve_device(db, user_id, device_id)
    node = await _get_node_or_404(db, node_id)
    await _guard_active_account(db, user_id)
    peer = await _ready_peer(db, device, node)
    return _amnezia_qr_response(device, node, peer, f'{user.name} / {device.name} / {node.name}')


# ── legacy routes, pinned to the migration Default device ──────────────────────


@router.get('/users/{user_id}/configs')
async def api_user_configs(user_id: str, db: DB):
    """Per-node config texts of the migration ``Default`` device; ``409`` without that device."""
    await _get_user_or_404(db, user_id)
    device = await _resolve_legacy_device(db, user_id)
    await _guard_active_account(db, user_id)
    return await _config_entries(db, device, await _nodes(db))


@router.get('/users/{user_id}/configs/zip')
async def api_user_configs_zip(user_id: str, db: DB):
    """Archive of every live device of the user, one folder per device.

    User-wide on purpose: the folder carries the device name *and* an id fragment, and entry names
    are deduplicated, so two devices with the same name (or two nodes sharing one) cannot collide.
    """
    user = await _get_user_or_404(db, user_id)
    devices = [
        device
        for device in (
            (await db.execute(select(Device).where(Device.user_id == user_id))).scalars().all()
        )
        if device.deleted_at is None
    ]
    await _guard_active_account(db, user_id)
    if not devices:
        raise HTTPException(status_code=409, detail=NOTHING_READY_DETAIL)
    return await _zip_response(
        db, devices, filename=f'{user.name}-configs.zip', folder_per_device=True
    )


@router.get('/users/{user_id}/configs/{node_id}')
async def api_user_config_for_node(user_id: str, node_id: str, db: DB):
    await _get_user_or_404(db, user_id)
    device = await _resolve_legacy_device(db, user_id)
    node = await _get_node_or_404(db, node_id)
    await _guard_active_account(db, user_id)
    return _awg_config_response(device, node, await _ready_peer(db, device, node))


@router.get('/users/{user_id}/qr/{node_id}')
async def api_user_qr(user_id: str, node_id: str, db: DB):
    await _get_user_or_404(db, user_id)
    device = await _resolve_legacy_device(db, user_id)
    node = await _get_node_or_404(db, node_id)
    await _guard_active_account(db, user_id)
    return _awg_qr_response(device, node, await _ready_peer(db, device, node))


@router.get('/users/{user_id}/qr-amnezia/{node_id}')
async def api_user_qr_amnezia(user_id: str, node_id: str, db: DB):
    user = await _get_user_or_404(db, user_id)
    device = await _resolve_legacy_device(db, user_id)
    node = await _get_node_or_404(db, node_id)
    await _guard_active_account(db, user_id)
    peer = await _ready_peer(db, device, node)
    return _amnezia_qr_response(device, node, peer, f'{user.name} / {node.name}')


# ── Peers (read-only from panel perspective) ──────────────────────────────────
