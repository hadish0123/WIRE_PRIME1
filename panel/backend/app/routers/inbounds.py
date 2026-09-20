from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.database import get_db
from app.models import Node
from app.routers.auth import has_permission, require_auth
from app.routers.api_parts.common import get_scoped_node, owner_filter

router = APIRouter(prefix='/api/inbounds', dependencies=[Depends(require_auth)])

class InboundIn(BaseModel):
    node_id: str
    protocol: str = Field(pattern=r'^(wireguard|openvpn)$')
    name: str = Field(min_length=1, max_length=64)
    endpoint: str | None = None
    port: int = Field(default=51820, ge=1, le=65535)
    network: str = Field(default='10.8.0.0/24')

def _guard(auth: dict, permission: str) -> None:
    if not has_permission(auth['_admin'], permission):
        raise HTTPException(status_code=403, detail='Permission denied')

@router.get('')
async def list_inbounds(auth: dict = Depends(require_auth), db=Depends(get_db)):
    _guard(auth, 'nodes.view')
    nodes = (await db.execute(select(Node).where(owner_filter(Node.owner_admin_id)).order_by(Node.name, Node.id))).scalars().all()
    result = []
    for node in nodes:
        result.append({'id': f'wireguard:{node.id}', 'node_id': node.id, 'node_name': node.name, 'protocol': 'wireguard', 'name': 'WireGuard / AmneziaWG', 'endpoint': node.server_endpoint, 'port': node.listen_port or 51820, 'network': '10.8.0.0/24', 'enabled': bool(node.server_public_key)})
        result.append({'id': f'openvpn:{node.id}', 'node_id': node.id, 'node_name': node.name, 'protocol': 'openvpn', 'name': 'OpenVPN', 'endpoint': None, 'port': 1194, 'network': '10.9.0.0/24', 'enabled': False})
    return result

@router.put('')
async def configure_inbound(data: InboundIn, auth: dict = Depends(require_auth), db=Depends(get_db)):
    _guard(auth, 'wireguard.manage' if data.protocol == 'wireguard' else 'openvpn.manage')
    node = await get_scoped_node(data.node_id, db)
    if data.protocol == 'wireguard':
        return {'id': f'wireguard:{node.id}', 'node_id': node.id, 'protocol': 'wireguard', 'name': data.name, 'status': 'ready', 'note': 'Uses the managed WireGuard/AmneziaWG interface on this node.'}
    if not data.endpoint:
        raise HTTPException(status_code=400, detail='OpenVPN endpoint is required')
    import httpx
    endpoint = data.endpoint if ':' in data.endpoint or data.endpoint.startswith('[') else f'{data.endpoint}:{data.port}'
    async with httpx.AsyncClient(timeout=30, headers={'Authorization': f'Bearer {node.token}'}) as client:
        response = await client.put(node.url.rstrip('/') + '/openvpn/server', json={'endpoint': endpoint, 'port': data.port, 'protocol': 'udp', 'network': data.network})
        response.raise_for_status()
        return {'id': f'openvpn:{node.id}', 'node_id': node.id, 'protocol': 'openvpn', 'name': data.name, **response.json()}
