import logging
import os
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from fastapi import APIRouter, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin').strip()
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
ALGORITHM = 'HS256'
TOKEN_EXPIRE = timedelta(hours=int(os.environ.get('TOKEN_EXPIRE_HOURS', '12')))

if not ADMIN_PASSWORD:
    log.warning('ADMIN_PASSWORD is not set — all login attempts will be rejected')
if not os.environ.get('SECRET_KEY'):
    log.warning('SECRET_KEY is not set — tokens will be invalidated on every restart')

_bearer = HTTPBearer()
router = APIRouter()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


@router.post('/api/auth/login')
def login(data: LoginRequest):
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=503, detail='ADMIN_PASSWORD is not configured on the server')
    if data.username != ADMIN_USERNAME or data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail='Invalid username or password')
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            'sub': data.username,
            'role': 'super_admin',
            'iat': now,
            'exp': now + TOKEN_EXPIRE,
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    return {'token': token, 'username': data.username, 'role': 'super_admin'}


def require_auth(
    creds: Annotated[HTTPAuthorizationCredentials, Security(_bearer)],
) -> dict:
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail='Invalid or expired token') from exc
    return payload
