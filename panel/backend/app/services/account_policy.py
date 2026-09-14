"""Effective account standing: one decision point for whether an account may use its devices.

The public page and device provisioning must agree on what an inactive account is, so both build
the answer from the same composition here: the local lifecycle (blocked, expired, limited) from
:mod:`app.services.local_lifecycle`, and the Remnawave lifecycle (disabled, expired, limited,
stale, deleted, plus the combined traffic limit). The ``code`` drives the HTTP answer - only
``active`` may download or add devices - and the ``reason`` is the diagnostic that is reported.

:func:`require_active_owner` is the write-path guard and is deliberately database-facing: its
caller holds the owner row lock, so the state that decides must be the one committed while the
lock was awaited, not a value this session's identity map cached earlier. The public add route's
own guard runs *before* the lock and can be raced by exactly that state change.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import RemnawaveUser, User
from app.services.local_lifecycle import (
    aware,
    load_local_total_bytes,
    local_user_blocked_reason,
    now,
)

# Remnawave status → public ``(code, reason)``. Public API contract: these values are what the
# user page and the account guard answer with.
REMNAWAVE_STATUS_CODES: dict[str, tuple[str, str]] = {
    'DISABLED': ('blocked', 'disabled'),
    'LIMITED': ('limited', 'limited'),
    'EXPIRED': ('expired', 'expired'),
}
LOCAL_REASON_CODES: dict[str, str] = {
    'blocked': 'blocked',
    'limited': 'limited',
    'expired': 'expired',
}
ACTIVE_STATUS: dict = {'code': 'active', 'reason': None}


class AccountInactiveError(RuntimeError):
    """Raised when an account may not own or use devices; the HTTP layer maps it to ``403``."""

    def __init__(self, *, code: str, reason: str | None) -> None:
        super().__init__(f'account is {code}' + (f' ({reason})' if reason else ''))
        self.code = code
        self.reason = reason


def local_account_status(user: User, local_total_bytes: int) -> dict:
    reason = local_user_blocked_reason(user, local_total_bytes)
    if reason is None:
        return dict(ACTIVE_STATUS)
    return {'code': LOCAL_REASON_CODES.get(reason, 'blocked'), 'reason': reason}


def remnawave_account_status(row: RemnawaveUser, local_total_bytes: int) -> dict:
    if row.delete_requested_at is not None or row.sync_status in {'missing', 'stale'}:
        return {'code': 'blocked', 'reason': 'deleted'}
    if row.status in REMNAWAVE_STATUS_CODES:
        code, reason = REMNAWAVE_STATUS_CODES[row.status]
        return {'code': code, 'reason': reason}
    if (
        row.traffic_limit_bytes > 0
        and row.traffic_used_bytes + local_total_bytes >= row.traffic_limit_bytes
    ):
        return {'code': 'limited', 'reason': 'limited'}
    expire_at = aware(row.expire_at)
    if expire_at is not None and expire_at <= now():
        return {'code': 'expired', 'reason': 'expired'}
    return dict(ACTIVE_STATUS)


def account_status(user: User, local_total_bytes: int, remnawave: RemnawaveUser | None) -> dict:
    """Effective ``{'code', 'reason'}`` of an owner, from its already-loaded rows.

    A Remnawave-managed account is judged by its imported profile - the local limit stays inert
    - and a local account by the local lifecycle; the caller passes the profile it holds.

    The local block flag is checked last for a Remnawave-managed owner, and only when the imported
    profile reports ``active``: a profile that has something to say (disabled, expired, limited,
    deleted) keeps its own diagnostic, while a block set locally - by an administrator, or by the
    lifecycle job while the import still says ACTIVE - is *added* rather than lost. Without that
    fallback the write guard would call such an owner active and provision a device for an account
    the page and every download route already refuse.
    """
    if remnawave is None:
        return local_account_status(user, local_total_bytes)
    status = remnawave_account_status(remnawave, local_total_bytes)
    if status['code'] != 'active':
        return status
    if user.is_blocked:
        return {'code': 'blocked', 'reason': 'blocked'}
    return status


async def _fresh_owner(db: AsyncSession, user_id: str) -> User | None:
    """The owner row's current committed state, even when the identity map holds an older copy.

    The statement carries the profile with it: ``populate_existing`` refreshes the row *and* the
    eagerly loaded relationship, so this is a fresh Remnawave state too - and, just as important,
    ``User.remnawave_user`` stays loaded on the instance other code shares instead of being expired
    into an async lazy load (which raises rather than loading).
    """
    return (
        await db.execute(
            select(User)
            .where(User.id == user_id)
            .options(selectinload(User.remnawave_user))
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def fresh_account_status(db: AsyncSession, user_id: str) -> dict:
    """The owner's effective status read straight from the database, not from loaded instances.

    Raises:
        ValueError: the owner no longer exists.
    """
    user = await _fresh_owner(db, user_id)
    if user is None:
        raise ValueError(f'user {user_id} not found')
    local_total_bytes = await load_local_total_bytes(db, user_id)
    return account_status(user, local_total_bytes, user.remnawave_user)


async def require_active_owner(db: AsyncSession, user_id: str) -> None:
    """Refuse a non-active owner, deciding on freshly read owner, profile and traffic rows.

    Callers must already hold the owner row lock (``app.services.devices.lock_owner``): the guard
    reads the state that was committed while the lock was awaited, so a block, expiry, traffic
    overrun or Remnawave status change committed by another transaction in that window is seen
    rather than missed.

    Raises:
        AccountInactiveError: carrying the public ``code``/``reason`` the HTTP layer reports.
        ValueError: the owner no longer exists.
    """
    status = await fresh_account_status(db, user_id)
    if status['code'] != 'active':
        raise AccountInactiveError(code=status['code'], reason=status['reason'])
