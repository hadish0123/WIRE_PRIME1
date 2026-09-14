import uuid
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Node, User


class RemnawaveUserProvisionData(Protocol):
    username: str
    short_uuid: str | None


async def list_nodes(db: AsyncSession) -> list[Node]:
    return list((await db.execute(select(Node))).scalars().all())


async def create_local_user(
    db: AsyncSession, name: str, *, is_blocked: bool = False, device_limit: int = 0
) -> User:
    """Create a local account with no key material, devices or peers.

    Devices are created explicitly (see ``app.services.devices``); provisioning must never invent
    them, so a brand new account owns nothing until an operator or the user adds a device. The
    optional ``device_limit`` is the account's local budget only - it never creates a device, and it
    is inert for a Remnawave-managed account.
    """
    user = User(name=name, is_blocked=is_blocked, device_limit=device_limit)
    db.add(user)
    await db.flush()
    return user


async def resolve_remnawave_username(db: AsyncSession, desired: str, short_uuid: str | None) -> str:
    existing = await db.execute(select(User).where(User.name == desired))
    if existing.scalar_one_or_none() is None:
        return desired
    suffix = short_uuid or str(uuid.uuid4())[:8]
    return f'{desired}__rw_{suffix}'


async def create_remnawave_local_user(
    db: AsyncSession,
    data: RemnawaveUserProvisionData,
    *,
    is_blocked: bool,
) -> tuple[User, set[str]]:
    """Create the local mirror of a Remnawave profile with no keys, devices or peers.

    The empty node-id set is returned so callers keep their "affected nodes" contract.
    """
    user = User(
        name=await resolve_remnawave_username(db, data.username, data.short_uuid),
        is_blocked=is_blocked,
    )
    db.add(user)
    await db.flush()
    return user, set()
