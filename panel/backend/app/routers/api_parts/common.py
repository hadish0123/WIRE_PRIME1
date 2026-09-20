from typing import Annotated

from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Admin, Node, User
from app.routers.auth import current_admin, is_super_admin, tenant_root

DB = Annotated[AsyncSession, Depends(get_db)]
REMNAWAVE_MANAGED_USER_CONFLICT_DETAIL = 'Remnawave-managed user cannot be modified locally'


async def guard_not_remnawave_managed(user: User) -> None:
    if user.remnawave_user is not None:
        raise HTTPException(
            status_code=409,
            detail=REMNAWAVE_MANAGED_USER_CONFLICT_DETAIL,
        )


def guard_tenant_owner(owner_admin_id: str | None) -> None:
    admin = current_admin()
    if admin is None:
        raise HTTPException(status_code=401, detail='Authentication required')
    if not is_super_admin(admin) and owner_admin_id != tenant_root(admin):
        raise HTTPException(status_code=404, detail='Resource not found')

def tenant_owner_for_create() -> str:
    admin = current_admin()
    if admin is None:
        raise HTTPException(status_code=401, detail='Authentication required')
    return tenant_root(admin)

def owner_filter(column):
    admin = current_admin()
    if admin is None:
        raise HTTPException(status_code=401, detail='Authentication required')
    return True if is_super_admin(admin) else column == tenant_root(admin)

async def get_scoped_user(user_id: str, db: DB) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail='User not found')
    guard_tenant_owner(user.owner_admin_id)
    return user

async def get_scoped_node(node_id: str, db: DB) -> Node:
    node = await db.get(Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail='Node not found')
    guard_tenant_owner(node.owner_admin_id)
    return node
