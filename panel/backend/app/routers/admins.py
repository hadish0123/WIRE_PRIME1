from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Admin
from app.routers.auth import has_permission, hash_password, require_auth

router = APIRouter(prefix='/api/admins', dependencies=[Depends(require_auth)])

class AdminIn(BaseModel):
    username: str = Field(min_length=3, max_length=128, pattern=r'^[A-Za-z0-9_.-]+$')
    password: str = Field(min_length=10, max_length=256)
    role: str = Field(default='sub_admin', pattern=r'^(super_admin|admin|sub_admin)$')
    permissions: list[str] = Field(default_factory=list)
    node_ids: list[str] = Field(default_factory=list)
    is_active: bool = True

class AdminUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=10, max_length=256)
    role: str | None = Field(default=None, pattern=r'^(super_admin|admin|sub_admin)$')
    permissions: list[str] | None = None
    node_ids: list[str] | None = None
    is_active: bool | None = None

class AdminOut(BaseModel):
    id: str
    username: str
    role: str
    permissions: list[str]
    node_ids: list[str]
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None

def _out(a: Admin) -> AdminOut:
    return AdminOut(
        id=a.id, username=a.username, role=a.role,
        permissions=json.loads(a.permissions_json or '[]'),
        node_ids=json.loads(a.node_ids_json or '[]'),
        is_active=a.is_active, created_at=a.created_at, last_login_at=a.last_login_at,
    )

def _guard(auth: dict, permission: str) -> Admin:
    admin = auth['_admin']
    if not has_permission(admin, permission):
        raise HTTPException(status_code=403, detail='Permission denied')
    return admin

@router.get('', response_model=list[AdminOut])
async def list_admins(auth: dict = Depends(require_auth), db: AsyncSession = Depends(get_db)):
    _guard(auth, 'admins.view')
    rows = (await db.execute(select(Admin).order_by(Admin.username))).scalars().all()
    return [_out(a) for a in rows]

@router.post('', response_model=AdminOut, status_code=201)
async def create_admin(data: AdminIn, auth: dict = Depends(require_auth), db: AsyncSession = Depends(get_db)):
    _guard(auth, 'admins.create')
    if data.role == 'super_admin' and auth['_admin'].role != 'super_admin':
        raise HTTPException(status_code=403, detail='Only super admin can create a super admin')
    if await db.scalar(select(Admin).where(Admin.username == data.username)):
        raise HTTPException(status_code=409, detail='Username already exists')
    admin = Admin(
        id=str(uuid.uuid4()), username=data.username, password_hash=hash_password(data.password),
        role=data.role, permissions_json=json.dumps(sorted(set(data.permissions))),
        node_ids_json=json.dumps(sorted(set(data.node_ids))), is_active=data.is_active,
        created_at=datetime.now(UTC),
    )
    db.add(admin)
    await db.commit()
    await db.refresh(admin)
    return _out(admin)

@router.patch('/{admin_id}', response_model=AdminOut)
async def update_admin(admin_id: str, data: AdminUpdate, auth: dict = Depends(require_auth), db: AsyncSession = Depends(get_db)):
    actor = _guard(auth, 'admins.edit')
    admin = await db.get(Admin, admin_id)
    if not admin:
        raise HTTPException(status_code=404, detail='Admin not found')
    if admin.role == 'super_admin' and actor.role != 'super_admin':
        raise HTTPException(status_code=403, detail='Only super admin can edit a super admin')
    for field, value in data.model_dump(exclude_unset=True).items():
        if field == 'password' and value:
            admin.password_hash = hash_password(value)
        elif field == 'permissions' and value is not None:
            admin.permissions_json = json.dumps(sorted(set(value)))
        elif field == 'node_ids' and value is not None:
            admin.node_ids_json = json.dumps(sorted(set(value)))
        elif value is not None:
            setattr(admin, field, value)
    if admin.id == actor.id and admin.is_active is False:
        raise HTTPException(status_code=400, detail='You cannot deactivate your own account')
    await db.commit()
    await db.refresh(admin)
    return _out(admin)

@router.delete('/{admin_id}', status_code=204)
async def delete_admin(admin_id: str, auth: dict = Depends(require_auth), db: AsyncSession = Depends(get_db)):
    actor = _guard(auth, 'admins.delete')
    if admin_id == actor.id:
        raise HTTPException(status_code=400, detail='You cannot delete your own account')
    admin = await db.get(Admin, admin_id)
    if not admin:
        raise HTTPException(status_code=404, detail='Admin not found')
    if admin.role == 'super_admin' and actor.role != 'super_admin':
        raise HTTPException(status_code=403, detail='Only super admin can delete a super admin')
    await db.delete(admin)
    await db.commit()
