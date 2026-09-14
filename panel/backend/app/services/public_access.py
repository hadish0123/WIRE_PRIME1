"""Who the public page is allowed to talk about: one token-or-id rule, two routers.

The page, its devices/download routes and the event stream must agree on this or the stream could
authorize a caller the page would answer ``404`` for. Keeping the lookup in one place is the whole
point of this module: :func:`resolve_public_user` is the only public identity rule.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import User


async def resolve_public_user(db: AsyncSession, token_or_id: str) -> User | None:
    """The owner behind a public URL segment - the rotatable ``public_token`` or the user id.

    ``None`` means "no such account": every caller must answer ``404`` without revealing whether the
    token or the id was the one that did not resolve.
    """
    return (
        await db.execute(
            select(User)
            .where((User.public_token == token_or_id) | (User.id == token_or_id))
            .options(selectinload(User.remnawave_user))
        )
    ).scalar_one_or_none()
