import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Admin

log = logging.getLogger(__name__)
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError('SECRET_KEY environment variable is required in production')
ALGORITHM = 'HS256'
TOKEN_EXPIRE = timedelta(hours=int(os.environ.get('TOKEN_EXPIRE_HOURS', '12')))
BOOTSTRAP_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin').strip()
BOOTSTRAP_PASSWORD = os.environ.get('ADMIN_PASSWORD')
_bearer = HTTPBearer()
router = APIRouter()
_CURRENT_ADMIN: ContextVar[Admin | None] = ContextVar('primevpn_current_admin', default=None)

ROLE_PERMISSIONS = {
    'super_admin': {'*'},
    'admin': {'nodes.view','nodes.create','nodes.edit','nodes.delete','users.view','users.create','users.edit','users.delete','users.disable','wireguard.manage','openvpn.manage','configs.view','configs.download','traffic.view','admins.view','admins.create','admins.edit','admins.delete','settings.view','settings.edit'},
    'sub_admin': {'nodes.view','users.view','users.create','users.edit','users.disable','wireguard.manage','openvpn.manage','configs.view','configs.download','traffic.view'},
}

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = 2**14, 8, 1
    digest = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=64)
    return 'scrypt$' + str(n) + '$' + str(r) + '$' + str(p) + '$' + base64.urlsafe_b64encode(salt).decode() + '$' + base64.urlsafe_b64encode(digest).decode()

def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, ns, rs, ps, salt_s, digest_s = encoded.split('$', 5)
        if scheme != 'scrypt':
            return False
        salt = base64.urlsafe_b64decode(salt_s.encode())
        expected = base64.urlsafe_b64decode(digest_s.encode())
        actual = hashlib.scrypt(password.encode(), salt=salt, n=int(ns), r=int(rs), p=int(ps), dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False

def role_permissions(admin: Admin) -> set[str]:
    try:
        raw = json.loads(admin.permissions_json or '[]')
        if isinstance(raw, list):
            return set(str(x) for x in raw) | ROLE_PERMISSIONS.get(admin.role, set())
    except json.JSONDecodeError:
        pass
    return set(ROLE_PERMISSIONS.get(admin.role, set()))

def tenant_root(admin: Admin) -> str:
    return admin.tenant_owner_id or admin.id

def is_super_admin(admin: Admin) -> bool:
    return admin.role == 'super_admin'

def owns_tenant(admin: Admin, owner_admin_id: str | None) -> bool:
    return is_super_admin(admin) or owner_admin_id == tenant_root(admin)

def current_admin() -> Admin | None:
    return _CURRENT_ADMIN.get()

def current_tenant_id() -> str | None:
    admin = current_admin()
    return tenant_root(admin) if admin else None

def is_current_super_admin() -> bool:
    admin = current_admin()
    return bool(admin and is_super_admin(admin))

def has_permission(admin: Admin, permission: str) -> bool:
    return '*' in role_permissions(admin) or permission in role_permissions(admin)

async def bootstrap_admin(db: AsyncSession) -> None:
    if not BOOTSTRAP_PASSWORD or not BOOTSTRAP_USERNAME:
        return
    admin = await db.scalar(select(Admin).where(Admin.username == BOOTSTRAP_USERNAME))
    if admin is None:
        admin = Admin(username=BOOTSTRAP_USERNAME, password_hash=hash_password(BOOTSTRAP_PASSWORD), role='super_admin', permissions_json='[]', node_ids_json='[]')
        db.add(admin)
        await db.flush()
        admin.tenant_owner_id = admin.id
        await db.commit()
        log.info('Created PRIMEVPN bootstrap super admin %s', BOOTSTRAP_USERNAME)

@router.post('/api/auth/login')
async def login(data: LoginRequest, db: AsyncSession = Depends(get_db)):
    admin = await db.scalar(select(Admin).where(Admin.username == data.username))
    if admin is None or not admin.is_active or not verify_password(data.password, admin.password_hash):
        raise HTTPException(status_code=401, detail='Invalid username or password')
    now = datetime.now(UTC)
    admin.last_login_at = now
    await db.commit()
    token = jwt.encode({'sub': admin.id, 'username': admin.username, 'role': admin.role, 'iat': now, 'exp': now + TOKEN_EXPIRE}, SECRET_KEY, algorithm=ALGORITHM)
    return {'token': token, 'username': admin.username, 'role': admin.role}

async def require_auth(creds: Annotated[HTTPAuthorizationCredentials, Security(_bearer)], db: AsyncSession = Depends(get_db)) -> dict:
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail='Invalid or expired token') from exc
    admin_id = str(payload.get('sub') or '')
    admin = await db.get(Admin, admin_id)
    if not admin or not admin.is_active:
        raise HTTPException(status_code=401, detail='Account is inactive or no longer exists')
    _CURRENT_ADMIN.set(admin)
    payload['_admin'] = admin
    return payload

async def require_permission(permission: str, auth: dict = Depends(require_auth)) -> dict:
    admin = auth['_admin']
    if not has_permission(admin, permission):
        raise HTTPException(status_code=403, detail='Permission denied')
    return auth

Auth = Annotated[dict, Depends(require_auth)]
