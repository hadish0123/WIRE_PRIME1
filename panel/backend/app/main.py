import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .error_handlers import register_error_handlers
from .routers import api, auth, internal_worker, remnawave, telegram_proxy, user_events, user_page
from .services.events import get_hub

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    hub = get_hub()
    await hub.start()
    try:
        yield
    finally:
        await hub.stop()


app = FastAPI(title='PRIMEVPN Control Plane', version='1.0.0')
register_error_handlers(app)
app.include_router(auth.router)
app.include_router(api.webhook_router)
app.include_router(api.router)
app.include_router(internal_worker.router)
app.include_router(remnawave.router)
app.include_router(telegram_proxy.router)
app.include_router(user_page.router)
app.include_router(user_events.router)
