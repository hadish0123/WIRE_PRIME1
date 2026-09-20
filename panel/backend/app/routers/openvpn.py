from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Admin, Node, OpenVPNClient, User
from app.routers.auth import has_permission, require_auth
from app.routers.api_parts.common import get_scoped_node, get_scoped_user, owner_filter, tenant_owner_for_create, guard_tenant_owner

router = APIRouter(prefix='/api/openvpn', dependencies=[Depends(require_auth)])
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$')

class ServerIn(BaseModel):
    node_id: str
    endpoint: str = Field(min_length=1, max_length=255)
    port: int = Field(default=1194, ge=1, le=65535)
    protocol: str = Field(default='udp', pattern=r'^(udp|tcp-server)$')
    network: str = Field(default='10.9.0.0/24')

class ClientIn(BaseModel):
    user_id: str | None = None
    node_id: str
    name: str = Field(min_length=1, max_length=32)
    traffic_gb: float = Field(default=0, ge=0, le=1000000)
    days: int = Field(default=0, ge=0, le=3650)

def _guard(auth: dict, permission: str) -> None:
    if not has_permission(auth['_admin'], permission):
        raise HTTPException(status_code=403, detail='Permission denied')

def _node_url(node: Node) -> str:
    if not node.url.startswith(('http://', 'https://')) or any(x in node.url for x in ('@', '\\n', '\\r')):
        raise HTTPException(status_code=400, detail='Invalid node URL')
    return node.url.rstrip('/')

async def _request(node: Node, method: str, path: str, **kwargs):
    try:
        async with httpx.AsyncClient(timeout=30, headers={'Authorization': f'Bearer {node.token}'}) as client:
            response = await client.request(method, _node_url(node) + path, **kwargs)
            response.raise_for_status()
            return response
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text[:500]
        raise HTTPException(status_code=502, detail=f'Node request failed: {detail}') from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail='Node is unreachable') from exc

@router.put('/server')
async def configure_server(data: ServerIn, auth: dict = Depends(require_auth), db: AsyncSession = Depends(get_db)):
    _guard(auth, 'openvpn.manage')
    try:
        network = ipaddress.ip_network(data.network, strict=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail='Invalid OpenVPN network') from exc
    if not network.is_private or network.version != 4:
        raise HTTPException(status_code=400, detail='OpenVPN network must be a private IPv4 network')
    node = await get_scoped_node(data.node_id, db)
    response = await _request(node, 'PUT', '/openvpn/server', json=data.model_dump())
    return response.json()

@router.get('/nodes/{node_id}/status')
async def status(node_id: str, auth: dict = Depends(require_auth), db: AsyncSession = Depends(get_db)):
    _guard(auth, 'nodes.view')
    node = await db.get(Node, node_id)
    if not node:
        raise HTTPException(status_code=404, detail='Node not found')
    return (await _request(node, 'GET', '/openvpn/status')).json()

@router.post('/clients', status_code=201)
async def create_client(data: ClientIn, auth: dict = Depends(require_auth), db: AsyncSession = Depends(get_db)):
    _guard(auth, 'openvpn.manage')
    if not NAME_RE.fullmatch(data.name):
        raise HTTPException(status_code=400, detail='Invalid OpenVPN client name')
    node = await db.get(Node, data.node_id)
    if not node:
        raise HTTPException(status_code=404, detail='Node not found')
    user = await get_scoped_user(data.user_id, db) if data.user_id else None
    if user is None:
        user = await db.scalar(select(User).where(User.name == data.name, owner_filter(User.owner_admin_id)))
        if user is None:
            user = User(name=data.name, owner_admin_id=tenant_owner_for_create())
            db.add(user)
            await db.flush()
    requested_limit = int(data.traffic_gb * 1024 * 1024 * 1024) if data.traffic_gb > 0 else 0
    if requested_limit and user.owner_admin_id:
        root = await db.get(Admin, user.owner_admin_id)
        if root and root.traffic_quota_bytes > 0:
            used = await db.scalar(select(__import__('sqlalchemy').func.coalesce(__import__('sqlalchemy').func.sum(User.traffic_limit_bytes), 0)).where(User.owner_admin_id == root.id, User.id != user.id))
            if int(used or 0) + requested_limit > root.traffic_quota_bytes:
                raise HTTPException(status_code=403, detail='Your traffic quota has been reached')
    user.traffic_limit_bytes = requested_limit
    user.expire_at = datetime.now(UTC) + timedelta(days=data.days) if data.days > 0 else None
    user.lifecycle_status = 'active'
    existing = await db.scalar(select(OpenVPNClient).where(OpenVPNClient.node_id == node.id, OpenVPNClient.name == data.name))
    if existing:
        raise HTTPException(status_code=409, detail='OpenVPN client already exists')
    response = await _request(node, 'POST', '/openvpn/clients', json={'name': data.name, 'traffic_bytes': requested_limit, 'expire_at': user.expire_at.isoformat() if user.expire_at else None})
    client = OpenVPNClient(id=str(uuid.uuid4()), user_id=user.id, node_id=node.id, name=data.name, status='active', created_at=datetime.now(UTC), owner_admin_id=tenant_owner_for_create())
    db.add(client)
    await db.commit()
    await db.refresh(client)
    return {'id': client.id, 'user_id': client.user_id, 'node_id': client.node_id, 'name': client.name, 'status': client.status, 'traffic_gb': data.traffic_gb, 'days': data.days, 'node_result': response.json()}

@router.get('/clients')
async def list_clients(auth: dict = Depends(require_auth), db: AsyncSession = Depends(get_db)):
    _guard(auth, 'configs.view')
    rows = (await db.execute(select(OpenVPNClient).where(OpenVPNClient.status == 'active', owner_filter(OpenVPNClient.owner_admin_id)).order_by(OpenVPNClient.created_at.desc()))).scalars().all()
    return [{'id': c.id, 'user_id': c.user_id, 'node_id': c.node_id, 'name': c.name, 'status': c.status, 'created_at': c.created_at} for c in rows]

@router.get('/clients/{client_id}/config')
async def download_client(client_id: str, auth: dict = Depends(require_auth), db: AsyncSession = Depends(get_db)):
    _guard(auth, 'configs.download')
    client = await db.get(OpenVPNClient, client_id)
    if not client or client.status != 'active' or guard_tenant_owner(client.owner_admin_id):
        raise HTTPException(status_code=404, detail='OpenVPN client not found')
    node = await db.get(Node, client.node_id)
    if not node:
        raise HTTPException(status_code=404, detail='Node not found')
    response = await _request(node, 'GET', f'/openvpn/clients/{client.name}/config')
    return Response(content=response.text, media_type='application/x-openvpn-profile', headers={'Content-Disposition': f'attachment; filename="{client.name}.ovpn"'})

@router.delete('/clients/{client_id}', status_code=204)
async def revoke_client(client_id: str, auth: dict = Depends(require_auth), db: AsyncSession = Depends(get_db)):
    _guard(auth, 'openvpn.manage')
    client = await db.get(OpenVPNClient, client_id)
    if not client or client.status != 'active':
        raise HTTPException(status_code=404, detail='OpenVPN client not found')
    node = await db.get(Node, client.node_id)
    if not node:
        raise HTTPException(status_code=404, detail='Node not found')
    await _request(node, 'DELETE', f'/openvpn/clients/{client.name}')
    client.status = 'revoked'
    client.revoked_at = datetime.now(UTC)
    await db.commit()
