"""The public page's change stream: one authorized, key-free SSE channel per account.

Deliberately its own router rather than another route on ``user_page``: the stream is the only
response on the public surface with a lifetime, a connection budget and a background hub, and it
must not drag a request-scoped database session along with it. The authorization rule is the page's
own (:func:`app.services.public_access.resolve_public_user`), re-checked on a timer for as long as
the stream is open.

The stream sends three things and nothing else:

- ``connected`` - once, with ``{'user_id', 'notifications'}``. The client re-reads ``/info`` on it,
  which also covers the reconnect itself and any notification lost while the stream was down.
- ``changed`` - ``{'reason'}`` after the database committed a change for this account. No keys, no
  configuration bodies, no user profile.
- ``unauthorized`` - once, when the token stopped resolving, after which the stream ends.
"""

import logging
from functools import partial
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.background import BackgroundTask

from app.database import get_session_factory
from app.services.events import (
    EventStreamsStoppedError,
    SubscriptionLimitExceededError,
    get_hub,
    user_event_stream,
)
from app.services.public_access import resolve_public_user

log = logging.getLogger(__name__)

router = APIRouter()

# A factory, not a session: a session dependency would be held - with its pooled connection - for as
# long as the stream lives, i.e. one connection per open tab.
SessionFactory = Annotated[async_sessionmaker[AsyncSession], Depends(get_session_factory)]

# ``no-store`` keeps caches out of the way; ``X-Accel-Buffering: no`` tells a buffering reverse
# proxy (nginx) to pass events through instead of accumulating them, which would otherwise hold the
# stream silent until the proxy's buffer filled up.
STREAM_HEADERS = {
    'Cache-Control': 'no-store, no-cache',
    'X-Accel-Buffering': 'no',
    'Content-Encoding': 'identity',
}


async def _resolve_user_id(
    factory: async_sessionmaker[AsyncSession], token_or_id: str
) -> str | None:
    """Resolve the account for one stream check in its own short session."""
    async with factory() as session:
        user = await resolve_public_user(session, token_or_id)
        return None if user is None else user.id


async def _authorize(factory: async_sessionmaker[AsyncSession], token_or_id: str) -> bool:
    return await _resolve_user_id(factory, token_or_id) is not None


@router.get('/pub/u/{user_id}/events')
async def pub_user_events(user_id: str, request: Request, factory: SessionFactory):
    """Server-sent change notifications for one public account.

    Authorization is exactly the page's rule - the rotatable public token or the user id, anything
    else is ``404`` - and it is re-checked for the life of the stream, so a regenerated token or a
    removed account closes the stream instead of leaving it open.
    """
    resolved_user_id = await _resolve_user_id(factory, user_id)
    if resolved_user_id is None:
        raise HTTPException(status_code=404)
    hub = get_hub()
    try:
        subscription = hub.subscribe(resolved_user_id)
    except SubscriptionLimitExceededError as exc:
        # Bounded per process: a client that cannot get a stream keeps its polling fallback, and the
        # browser's own reconnect backoff replaces a hot retry loop.
        raise HTTPException(status_code=503, detail='Too many open event streams') from exc
    except EventStreamsStoppedError as exc:
        # The process is shutting down: a stream opened now would never be notified, so the client
        # must stay on its polling until the next request reaches a process that is serving.
        raise HTTPException(status_code=503, detail='Event streams are unavailable') from exc
    return StreamingResponse(
        user_event_stream(
            subscription,
            authorize=partial(_authorize, factory, user_id),
            hub=hub,
            is_disconnected=request.is_disconnected,
        ),
        media_type='text/event-stream',
        headers=STREAM_HEADERS,
        # The generator releases its subscription on every exit path, but a response that never
        # starts producing - the client is gone before the first frame - never runs the generator at
        # all. ``unsubscribe`` is idempotent, so releasing it here as well costs nothing.
        background=BackgroundTask(hub.unsubscribe, subscription),
    )
