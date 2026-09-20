import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import select, text

from .database import AsyncSessionLocal, ensure_tenant_schema
from .error_handlers import register_error_handlers
from .routers import admins, api, openvpn, auth, internal_worker, remnawave, telegram_proxy, user_events, user_page
from .services.events import get_hub

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await ensure_tenant_schema()
    async with AsyncSessionLocal() as db:
        await auth.bootstrap_admin(db)
        # Migrate pre-tenant records into the platform owner's tenant.
        owner = await db.scalar(select(auth.Admin).where(auth.Admin.role == 'super_admin').order_by(auth.Admin.created_at))
        if owner:
            await db.execute(text("UPDATE admins SET tenant_owner_id=:o WHERE tenant_owner_id IS NULL"), {'o': owner.id})
            await db.execute(__import__('sqlalchemy').text("UPDATE nodes SET owner_admin_id=:o WHERE owner_admin_id IS NULL"), {'o': owner.id})
            await db.execute(__import__('sqlalchemy').text("UPDATE users SET owner_admin_id=:o WHERE owner_admin_id IS NULL"), {'o': owner.id})
            await db.execute(__import__('sqlalchemy').text("UPDATE openvpn_clients SET owner_admin_id=:o WHERE owner_admin_id IS NULL"), {'o': owner.id})
            await db.commit()
    hub = get_hub()
    await hub.start()
    try:
        yield
    finally:
        await hub.stop()


app = FastAPI(title='PRIMEVPN Control Plane', version='100.0.0', lifespan=lifespan)
register_error_handlers(app)
@app.get('/health')
def health():
    return {'status': 'ok'}

app.include_router(auth.router)
app.include_router(admins.router)
app.include_router(openvpn.router)
app.include_router(api.webhook_router)
app.include_router(api.router)
app.include_router(internal_worker.router)
app.include_router(remnawave.router)
app.include_router(telegram_proxy.router)
app.include_router(user_page.router)
app.include_router(user_events.router)
