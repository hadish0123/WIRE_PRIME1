import os
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.environ['DATABASE_URL']

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """The session factory for code that opens its own short sessions.

    A request dependency would tie a session - and its pooled connection - to the response it
    produces; the public event stream outlives any response body and must therefore borrow a session
    briefly instead of holding one. Tests override this together with ``get_db``.
    """
    return AsyncSessionLocal


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession]:
    async with AsyncSessionLocal() as session:
        yield session


async def ensure_tenant_schema() -> None:
    """Idempotently add tenant isolation columns to an existing PRIMEVPN database."""
    statements = [
        "ALTER TABLE admins ADD COLUMN IF NOT EXISTS tenant_owner_id VARCHAR",
        "ALTER TABLE admins ADD COLUMN IF NOT EXISTS user_quota INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE admins ADD COLUMN IF NOT EXISTS traffic_quota_bytes BIGINT NOT NULL DEFAULT 0",
        "CREATE INDEX IF NOT EXISTS ix_admins_tenant_owner_id ON admins (tenant_owner_id)",
        "ALTER TABLE nodes ADD COLUMN IF NOT EXISTS owner_admin_id VARCHAR",
        "CREATE INDEX IF NOT EXISTS ix_nodes_owner_admin_id ON nodes (owner_admin_id)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS owner_admin_id VARCHAR",
        "CREATE INDEX IF NOT EXISTS ix_users_owner_admin_id ON users (owner_admin_id)",
        "ALTER TABLE openvpn_clients ADD COLUMN IF NOT EXISTS owner_admin_id VARCHAR",
        "CREATE INDEX IF NOT EXISTS ix_openvpn_clients_owner_admin_id ON openvpn_clients (owner_admin_id)",
    ]
    async with engine.begin() as conn:
        for statement in statements:
            await conn.execute(text(statement))
