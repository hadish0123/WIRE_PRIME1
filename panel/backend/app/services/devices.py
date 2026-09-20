"""Device ownership: creation, limits, IP allocation, deletion and peer provisioning.

A device owns its keypair, VPN IP and peers; the user keeps lifecycle, limits and traffic. Limits
are enforced under a lock on the owner row and deletion is a tombstone that frees the limit slot
immediately while keeping identity, IP, peers and traffic history for accounting.

This module also holds the *single* definition of the derived facts every surface needs: the
effective device limit and the per-device/per-node readiness rules. The admin API and the public
page must agree on when a configuration is downloadable and on what a limit means, so neither of
them re-implements either rule.

Uniqueness semantics, exactly as the database implements them: ``devices.vpn_ip`` is unique among
devices, ``devices.public_key`` is unique among devices, and ``peers`` carry a composite ownership
foreign key so a peer can never point at a device of another user. The pre-migration per-user
keypair/IP columns are frozen after migration 0019 - this module never reads or writes them.
They reserve nothing: 0019 copied each address onto the account's Default device, so only
``devices.vpn_ip`` is looked at when allocating. There is deliberately no cross-table uniqueness
constraint between legacy user key material and device key material.

The subnet is finite, so addresses are recycled rather than reserved forever: a tombstoned device
hands its address back - :func:`release_device_ip` - only once every one of its peers is confirmed
``deleted`` on the node that held it, which keeps the key material, the peer rows, the PSKs, the
traffic history and the released address itself on record.
"""

from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.crypto import VPN_SUBNET, allocate_ip, generate_keypair, generate_psk
from app.models import (
    AdminDevice,
    Device,
    DeviceNodeAvailability,
    Node,
    Peer,
    RemnawaveUser,
    User,
)

DEFAULT_DEVICE_NAME = 'Default'
MAX_IP_ALLOCATION_ATTEMPTS = 5

# Peer statuses as the download paths judge them: a live peer can serve a configuration once the
# node acknowledged it, and a tombstoned device's peer is on its way out.
LIVE_PEER_STATUSES = frozenset({'pending', 'active'})
DELETING_PEER_STATUSES = frozenset({'pending_delete', 'deleted'})
PENDING_CONFIG_DETAIL = 'Configuration not yet available'
DELETING_DEVICE_STATUS = 'deleting'


class DeviceLimitExceededError(RuntimeError):
    """Raised when the owner's effective device limit is already reached."""

    def __init__(self, *, limit: int, current: int) -> None:
        super().__init__(f'device limit {limit} already reached with {current} device(s)')
        self.limit = limit
        self.current = current


class DeviceIpAllocationError(RuntimeError):
    """Raised when a unique VPN IP could not be reserved within the bounded retry budget."""

    def __init__(self, attempts: int) -> None:
        super().__init__(f'could not allocate a unique VPN IP after {attempts} attempt(s)')
        self.attempts = attempts


class DeviceIpPoolExhaustedError(RuntimeError):
    """Raised when the finite VPN subnet has no address to hand out.

    This is a state of the deployment, not a bug: every address is held by a live device or by a
    deleted device whose removal no node has confirmed yet. The HTTP layer answers ``503`` for it so
    the operator sees "the pool is full right now" instead of an unexplained server error.
    """

    def __init__(self, subnet: str) -> None:
        super().__init__(
            f'VPN address pool {subnet} is exhausted: '
            'every client address is held by a live device '
            'or by a deleted device whose node has not yet confirmed removal'
        )
        self.subnet = subnet


def now() -> datetime:
    return datetime.now(UTC)


async def _lock_user_row(db: AsyncSession, user_id: str) -> User | None:
    """Lock the owner row, or ``None`` when the owner no longer exists.

    ``populate_existing`` makes the returned instance the row's committed state even when the
    identity map already holds an older copy: after waiting for the lock, callers must decide on
    what another transaction committed, not on what this session loaded before that commit. The
    profile is loaded with the row for the same reason - refreshing the owner must not expire the
    shared instance's ``remnawave_user`` relationship, whose async lazy load would raise.
    """
    return (
        await db.execute(
            select(User)
            .where(User.id == user_id)
            .options(selectinload(User.remnawave_user))
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def lock_owner(db: AsyncSession, user_id: str) -> User:
    """Lock the owner row so limit checks and device inserts are serialized per user.

    ``FOR UPDATE`` is a no-op on SQLite (tests) and a real row lock on PostgreSQL, where it is the
    point: two simultaneous adds cannot both observe the same free slot.

    Lock order is always owner row -> device row -> peer rows (the order :func:`delete_device`
    uses), which is also the order device creation and node sync acquire locks, so no two paths
    deadlock.
    """
    user = await _lock_user_row(db, user_id)
    if user is None:
        raise ValueError(f'user {user_id} not found')
    return user


def resolve_effective_device_limit(
    *,
    local_device_limit: int | None,
    imported_hwid_device_limit: int | None,
    is_remnawave_managed: bool,
) -> int | None:
    """The single limit rule, expressed on already-read values.

    The owner's *kind* decides the rule, not whether a value happens to be present: a
    Remnawave-managed owner is judged by its imported ``hwid_device_limit`` alone, so the local
    per-user column stays inert for it and is deliberately never a fallback - an imported null (or
    ``0``) means unlimited instead of accidentally surfacing that stale local number. A local owner
    is judged by its own column. ``None`` and ``0`` both mean unlimited, reported as ``None`` here
    and as ``0`` over HTTP.
    """
    if is_remnawave_managed:
        imported = imported_hwid_device_limit or 0
        return imported if imported > 0 else None
    local = local_device_limit or 0
    return local if local > 0 else None


def owner_effective_device_limit(user: User) -> int | None:
    """Effective device limit for an owner whose ``remnawave_user`` is already loaded.

    Loading is the caller's job on purpose: touching the relationship lazily inside an async request
    would raise, and the callers that need this (the admin list, the limit write) already select the
    profile eagerly.
    """
    remnawave = user.remnawave_user
    return resolve_effective_device_limit(
        local_device_limit=user.device_limit,
        imported_hwid_device_limit=remnawave.hwid_device_limit if remnawave is not None else None,
        is_remnawave_managed=remnawave is not None,
    )


async def effective_device_limit(db: AsyncSession, user_id: str) -> int | None:
    """Effective device limit for the owner, or ``None`` for unlimited.

    Remnawave-managed users use only the imported ``hwid_device_limit``; the presence of the
    imported profile is what selects that rule, so the local per-user ``device_limit`` cannot leak
    back in when the imported limit is ``null``.
    """
    row = (
        await db.execute(
            select(User.device_limit, RemnawaveUser.id, RemnawaveUser.hwid_device_limit)
            .outerjoin(RemnawaveUser, RemnawaveUser.user_id == User.id)
            .where(User.id == user_id)
        )
    ).first()
    if row is None:
        return None
    local_device_limit, imported_profile_id, imported_hwid_device_limit = row
    return resolve_effective_device_limit(
        local_device_limit=local_device_limit,
        imported_hwid_device_limit=imported_hwid_device_limit,
        is_remnawave_managed=imported_profile_id is not None,
    )


async def count_live_devices(db: AsyncSession, user_id: str) -> int:
    """Number of devices that still count against the limit.

    Tombstoned devices are excluded, pending ones are not: a device counts from the moment it is
    created, before its peers are acknowledged.
    """
    return int(
        await db.scalar(
            select(func.count())
            .select_from(Device)
            .where(Device.user_id == user_id, Device.deleted_at.is_(None))
        )
        or 0
    )


async def assert_device_capacity(db: AsyncSession, user_id: str) -> None:
    limit = await effective_device_limit(db, user_id)
    if limit is None:
        return
    current = await count_live_devices(db, user_id)
    if current >= limit:
        raise DeviceLimitExceededError(limit=limit, current=current)


async def allocate_device_ip(db: AsyncSession) -> str:
    """Next free VPN IP: the address no live or still-reserving device holds.

    Only ``devices.vpn_ip`` reserves an address. The frozen legacy ``users.vpn_ip`` column is
    deliberately ignored: migration 0019 copied each of those addresses onto the account's Default
    device, so honouring it a second time would keep an address busy forever after that device's
    address was legitimately released. ``released_vpn_ip`` is history and never reserves anything.

    The address space is finite (~250 clients in a ``/24``), so exhaustion is a real state: it is
    reported as :class:`DeviceIpPoolExhaustedError` instead of a bare ``RuntimeError``.
    """
    reserving = set(
        (await db.execute(select(Device.vpn_ip).where(Device.vpn_ip.isnot(None)))).scalars()
    )
    try:
        return allocate_ip({ip for ip in reserving if ip})
    except RuntimeError as exc:  # app.crypto.allocate_ip: the subnet is exhausted
        raise DeviceIpPoolExhaustedError(VPN_SUBNET) from exc


async def release_device_ip(
    db: AsyncSession, device: Device, *, at: datetime | None = None
) -> bool:
    """Hand a tombstoned device's VPN IP back to the pool, if and only if it is safe.

    Safe means the device is tombstoned *and* every peer is confirmed ``deleted``: a peer that
    is still ``pending``, ``active``, ``pending_delete`` or in any unknown state may still be
    installed on some node, and reusing its address would put two tunnels on one address. A device
    with no peer rows at all has nothing left anywhere and is safe immediately.

    Only ``vpn_ip`` is cleared. The keypair, every peer row (with its PSK, counters and traffic
    history) and the address itself (``released_vpn_ip`` + ``ip_released_at``) are kept, so nothing
    the node side keys off changes and the account's history survives. Idempotent, and it never
    touches a live device - a blocked owner's live device keeps its address.
    """
    if device.deleted_at is None or not device.vpn_ip:
        return False
    statuses = set(
        (await db.execute(select(Peer.status).where(Peer.device_id == device.id))).scalars()
    )
    if statuses and statuses != {'deleted'}:
        return False
    device.released_vpn_ip = device.vpn_ip
    device.ip_released_at = at or now()
    device.vpn_ip = None
    return True


async def release_device_ips(
    db: AsyncSession, device_ids: Iterable[str], *, at: datetime | None = None
) -> set[str]:
    """Release the addresses of the named devices that are safe to release, bounded to those ids.

    Callers pass the devices their own transaction just touched - a confirmed peer removal, a device
    deletion, a node removal. There is deliberately no global ``WHERE deleted_at IS NOT NULL`` scan:
    a bounded lookup keeps allocation free of whole-table work and of locking rows an unrelated
    transaction holds. Rows are locked in the documented order (by id), and the caller has already
    locked the owners and devices of these peers.
    """
    ids = {device_id for device_id in device_ids if device_id}
    if not ids:
        return set()
    devices = (
        (
            await db.execute(
                select(Device)
                .where(Device.id.in_(ids))
                .order_by(Device.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    released: set[str] = set()
    for device in devices:
        if await release_device_ip(db, device, at=at):
            released.add(device.id)
    return released


def _is_vpn_ip_conflict(exc: IntegrityError) -> bool:
    message = str(exc.orig if exc.orig is not None else exc)
    return 'uq_devices_vpn_ip' in message or 'devices.vpn_ip' in message


async def _insert_device_with_unique_ip(
    db: AsyncSession,
    *,
    user_id: str,
    name: str,
    public_key: str,
    private_key: str,
) -> Device:
    """Insert a device, retrying on the database-level unique-IP guarantee.

    The unique index (not the pre-read set) is the source of truth, so a concurrent allocator can
    only cost an attempt, never a duplicate IP.
    """
    for _ in range(MAX_IP_ALLOCATION_ATTEMPTS):
        device = Device(
            user_id=user_id,
            name=name,
            public_key=public_key,
            private_key=private_key,
            vpn_ip=await allocate_device_ip(db),
        )
        try:
            async with db.begin_nested():
                db.add(device)
                await db.flush()
        except IntegrityError as exc:
            if not _is_vpn_ip_conflict(exc):
                raise
            continue
        return device
    raise DeviceIpAllocationError(MAX_IP_ALLOCATION_ATTEMPTS)


async def create_device(db: AsyncSession, user_id: str, *, name: str, node_ids: Iterable[str] | None = None) -> tuple[Device, set[str]]:
    """Create a named device with fresh credentials, plus pending peers on every node.

    Returns the device and the node ids that now have a pending peer for it, so the caller can queue
    node syncs. The owner row is locked before the limit check and the insert, and the device stops
    counting only when it is deleted.

    The effective account state is re-checked *under that lock* before any key, IP, device or peer
    row is written: a request's earlier guard runs before the lock and a block, expiry, traffic
    limit or Remnawave status change committed while this transaction waited for the lock would
    otherwise still provision. :class:`app.services.account_policy.AccountInactiveError` is raised
    for such an owner and the HTTP layer answers ``403``.

    Runtime creation never sets ``is_legacy_default``: that flag means "inherited the pre-migration
    per-user credentials" and only migration 0019 may set it.
    """
    await lock_owner(db, user_id)
    # Imported here rather than at module level: the policy reads the local lifecycle, which
    # imports this module, so a top-level import would close a cycle. The check must run after the
    # owner row is locked, which is also where this call sits.
    from app.services.account_policy import require_active_owner

    await require_active_owner(db, user_id)
    await assert_device_capacity(db, user_id)
    private_key, public_key = generate_keypair()
    device = await _insert_device_with_unique_ip(
        db, user_id=user_id, name=name, public_key=public_key, private_key=private_key
    )
    owner = await db.get(User, user_id)
    node_ids = await create_pending_peers_for_device(db, device, node_ids=node_ids, owner_admin_id=owner.owner_admin_id if owner else None)
    return device, node_ids


async def create_pending_peer(db: AsyncSession, *, node_id: str, device: Device) -> bool:
    """Create the pending peer of ``device`` on ``node_id``; ``False`` if it does not apply.

    Refuses tombstoned devices on every call path, not only through node enumeration, so nothing can
    provision a peer for a deleted device. Devices without usable identity material are skipped.
    """
    if device.deleted_at is not None:
        return False
    existing = await db.scalar(
        select(Peer.id).where(Peer.node_id == node_id, Peer.device_id == device.id)
    )
    if existing is not None:
        return False
    if not device.public_key or not device.vpn_ip:
        return False

    try:
        async with db.begin_nested():
            db.add(
                Peer(
                    node_id=node_id,
                    user_id=device.user_id,
                    device_id=device.id,
                    status='pending',
                    psk_key=generate_psk(),
                )
            )
            await db.flush()
    except IntegrityError:
        return False
    return True


async def create_pending_peers_for_device(
    db: AsyncSession, device: Device, *, node_ids: Iterable[str] | None = None, owner_admin_id: str | None = None
) -> set[str]:
    if node_ids is not None:
        nodes = list(node_ids)
    else:
        stmt = select(Node.id)
        if owner_admin_id:
            stmt = stmt.where(Node.owner_admin_id == owner_admin_id)
        nodes = list((await db.execute(stmt)).scalars())
    created: set[str] = set()
    for node_id in nodes:
        if await create_pending_peer(db, node_id=node_id, device=device):
            created.add(node_id)
    return created


def _live_device_filters() -> tuple:
    return (
        Device.deleted_at.is_(None),
        Device.public_key.isnot(None),
        Device.vpn_ip.isnot(None),
        User.is_blocked == False,  # noqa: E712
    )


async def create_pending_peers_for_node(db: AsyncSession, node: Node) -> set[str]:
    """Create pending peers for every live device on a new/recreated node.

    Devices of blocked users and tombstoned devices are skipped, so a new node never inherits
    deleted or suspended identities.
    """
    stmt = select(Device).join(User, Device.user_id == User.id).where(*_live_device_filters())
    if node.owner_admin_id:
        stmt = stmt.where(User.owner_admin_id == node.owner_admin_id)
    devices = (await db.execute(stmt)).scalars().all()
    created: set[str] = set()
    for device in devices:
        if await create_pending_peer(db, node_id=node.id, device=device):
            created.add(device.id)
    return created


async def restore_missing_peers_for_user(db: AsyncSession, user_id: str) -> set[str]:
    """Give an owner's live devices the pending peers they are missing on existing nodes.

    Used on the blocked -> active transition: while the owner was blocked no peer was created for a
    node that appeared, and every existing peer was marked for removal. Recovery must restore the
    known peers (the caller does that) and provision the ones that never existed.

    Never creates a device - an account without devices still owns nothing afterwards - and
    tombstoned devices are excluded by :func:`list_live_devices`, so recovery cannot resurrect
    deleted credentials. A device without usable key material is skipped by
    :func:`create_pending_peer` rather than half-provisioned.

    Returns the node ids that gained a peer, so the caller can queue them like any other change.
    """
    created: set[str] = set()
    for device in await list_live_devices(db, user_id):
        created |= await create_pending_peers_for_device(db, device)
    return created


async def list_live_devices(db: AsyncSession, user_id: str) -> list[Device]:
    return list(
        (
            await db.execute(
                select(Device)
                .where(Device.user_id == user_id, Device.deleted_at.is_(None))
                .order_by(Device.created_at, Device.id)
            )
        )
        .scalars()
        .all()
    )


def live_devices(devices: Iterable[Device]) -> list[Device]:
    """The devices that still count against the limit, from already-loaded rows.

    The in-memory twin of :func:`count_live_devices` for the admin list, which must not issue a
    count query per owner.
    """
    return [device for device in devices if device.deleted_at is None]


async def get_legacy_default_device(db: AsyncSession, user_id: str) -> Device | None:
    """The device that inherited the pre-migration per-user credentials, if it exists.

    Resolved through the durable ``is_legacy_default`` marker, never by display name.
    """
    return (
        (
            await db.execute(
                select(Device)
                .where(Device.user_id == user_id, Device.is_legacy_default == True)  # noqa: E712
                .order_by(Device.created_at, Device.id)
            )
        )
        .scalars()
        .first()
    )


async def tombstoned_device_ids(db: AsyncSession, device_ids: Iterable[str]) -> set[str]:
    """Subset of ``device_ids`` whose device is tombstoned and must never be resurrected."""
    ids = {device_id for device_id in device_ids if device_id}
    if not ids:
        return set()
    rows = await db.execute(
        select(Device.id).where(Device.id.in_(ids), Device.deleted_at.isnot(None))
    )
    return set(rows.scalars())


async def delete_device(
    db: AsyncSession, device: Device, *, at: datetime | None = None
) -> set[str]:
    """Tombstone a device and mark its peers for removal.

    The limit slot is released immediately (the tombstone is what the limit counts) while the device
    row, its IP and all peer/traffic history stay. Returns the node ids whose peers must be removed.

    Locks are taken in the documented order - owner row, device row, then the device's peer rows
    ordered by id - so this cannot deadlock against device creation (owner row) or against an
    in-flight sync/heartbeat result, which locks the same peer rows. Holding the peer lock is what
    makes deletion and node results serialize: whichever side commits first wins, and the other one
    re-reads the committed row.

    ``Device.deleted_at`` is re-read under the lock and is the authoritative tombstone, so peers are
    re-marked for removal even when this is called a second time or when an earlier stale write left
    one live again. Idempotent: a device whose peers are already going away returns no node ids.
    """
    await _lock_user_row(db, device.user_id)
    locked_device = (
        await db.execute(select(Device).where(Device.id == device.id).with_for_update())
    ).scalar_one_or_none()
    if locked_device is None:
        return set()
    if locked_device.deleted_at is None:
        locked_device.deleted_at = at or now()

    affected_node_ids: set[str] = set()
    peers = (
        (
            await db.execute(
                select(Peer)
                .where(Peer.device_id == locked_device.id)
                .order_by(Peer.id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for peer in peers:
        if peer.status in {'pending', 'active'}:
            peer.status = 'pending_delete'
            affected_node_ids.add(peer.node_id)
    # A device with no peer at all - or whose peers are already confirmed gone - has nothing left on
    # any node, so its address goes back to the pool the moment it is tombstoned. With peers still
    # going away the release is a no-op; the node result that confirms the last removal releases it.
    await release_device_ip(db, locked_device)
    return affected_node_ids


async def delete_device_by_id(db: AsyncSession, device_id: str) -> tuple[Device | None, set[str]]:
    """API-facing wrapper around :func:`delete_device` that resolves the device first."""
    device = await db.get(Device, device_id)
    if device is None:
        return None, set()
    return device, await delete_device(db, device)


# ── readiness (one rule for the admin API and the public page) ─────────────────


async def get_device_peer(db: AsyncSession, device_id: str, node_id: str) -> Peer | None:
    """The peer of one device on one node - the ``uq_peers_node_device`` row, exactly one.

    The lookup key is the device, never the owner: with several devices per owner a peer can only be
    identified by ``(device_id, node_id)``, and asking for it by ``user_id`` would be ambiguous.
    """
    return (
        await db.execute(select(Peer).where(Peer.device_id == device_id, Peer.node_id == node_id))
    ).scalar_one_or_none()


def node_metadata_cached(node: Node) -> bool:
    """Whether the node's cached interface metadata is complete enough to build a config."""
    return bool(node.server_public_key and node.server_endpoint)


def device_credentials_ready(device: Device) -> bool:
    return bool(device.private_key and device.public_key and device.vpn_ip)


def peer_available(node: Node, device: Device, peer: Peer | None) -> bool:
    """Whether this device's config can actually be served from this node right now.

    Availability is deliberately *independent* of the node's diagnostic sync state: a peer the node
    already acknowledged stays usable for its owner while a later sync of that same node fails,
    because the acknowledgement, the peer's PSK, the cached node metadata and the device credentials
    are all still on record and the device is not tombstoned.
    """
    return (
        device.deleted_at is None
        and peer is not None
        and peer.status == 'active'
        and node_metadata_cached(node)
        and device_credentials_ready(device)
    )


def node_status(node: Node, device: Device, peer: Peer | None) -> str:
    """Per-node *diagnostic* state, derived from the peer and node rows only.

    ``error`` follows the node's own last sync and is therefore reported even for a peer that has
    not been applied yet; whether the device is *usable* is the separate question
    :func:`peer_available` answers, so a failed sync is visible without taking a working config
    away. There is no separate device status column: a node is ``ready`` once its peer is
    acknowledged active with cached metadata and usable credentials, and ``pending`` while the peer
    still has to be applied. ``deleting`` follows a tombstoned device's peer.
    """
    if peer is not None and peer.status in DELETING_PEER_STATUSES:
        return DELETING_DEVICE_STATUS
    if node.sync_status == 'failed':
        return 'error'
    if peer is None or peer.status == 'pending':
        return 'pending'
    if peer_available(node, device, peer):
        return 'ready'
    return 'pending'


def aggregate_device_status(statuses: Iterable[str], *, any_ready: bool) -> str:
    """Aggregate device state: usable as soon as one of its nodes is downloadable.

    ``ready`` availability decides, not the diagnostic string: a node whose last sync failed is
    reported as ``error`` while still serving its acknowledged peer, and the device stays usable.
    Only when nothing is usable do the diagnostics decide the aggregate.
    """
    if any_ready:
        return 'ready'
    unique = set(statuses)
    if 'ready' in unique:
        return 'ready'
    if 'error' in unique:
        return 'error'
    if unique and unique <= {DELETING_DEVICE_STATUS}:
        return DELETING_DEVICE_STATUS
    return 'pending'


def peers_by_device(peers: Iterable[Peer]) -> dict[str, dict[str, Peer]]:
    """Peers grouped as device id -> node id -> peer, i.e. by the ``uq_peers_node_device`` key."""
    grouped: dict[str, dict[str, Peer]] = {}
    for peer in peers:
        grouped.setdefault(peer.device_id, {})[peer.node_id] = peer
    return grouped


def device_node_availability(
    device: Device, nodes: Iterable[Node], peer_by_node_id: dict[str, Peer]
) -> list[DeviceNodeAvailability]:
    entries = []
    for node in nodes:
        peer = peer_by_node_id.get(node.id)
        entries.append(
            DeviceNodeAvailability(
                node_id=node.id,
                node_name=node.name,
                status=node_status(node, device, peer),
                ready=peer_available(node, device, peer),
            )
        )
    return entries


def device_views(
    devices: Iterable[Device], nodes: Iterable[Node], peers: Iterable[Peer]
) -> list[AdminDevice]:
    """Non-secret admin view of devices: identity plus per-node availability.

    Built from rows the caller already loaded, so a list of owners costs no extra queries. ``nodes``
    is the full ordered node list, which is what makes a node without a peer for this device show
    up as ``pending`` instead of silently disappearing. No key material is included: readiness
    needs the credentials, exposing them is a separate, explicitly-scoped decision (the config
    routes).

    The result is the ``AdminDevice`` schema itself rather than a loose mapping, so the admin API
    cannot hand a differently-shaped dict to a caller that typed it as ``AdminDevice``: there is one
    definition of the view and it is the one that is serialized.
    """
    node_list = list(nodes)
    grouped = peers_by_device(peers)
    result = []
    for device in devices:
        entries = device_node_availability(device, node_list, grouped.get(device.id, {}))
        result.append(
            AdminDevice(
                id=device.id,
                name=device.name,
                vpn_ip=device.vpn_ip,
                is_legacy_default=device.is_legacy_default,
                created_at=device.created_at,
                status=aggregate_device_status(
                    (entry.status for entry in entries),
                    any_ready=any(entry.ready for entry in entries),
                ),
                nodes=entries,
            )
        )
    return result


async def live_device_views(db: AsyncSession, user_id: str) -> list[AdminDevice]:
    """The same view for one owner, loading its live devices, every node and their peers."""
    devices = await list_live_devices(db, user_id)
    if not devices:
        return []
    nodes = (await db.execute(select(Node).order_by(Node.name, Node.id))).scalars().all()
    peers = (
        (
            await db.execute(
                select(Peer).where(Peer.device_id.in_([device.id for device in devices]))
            )
        )
        .scalars()
        .all()
    )
    return device_views(devices, nodes, peers)
