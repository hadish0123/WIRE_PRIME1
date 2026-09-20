import os
import re
import subprocess
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

router = APIRouter(prefix='/openvpn')
_bearer = HTTPBearer()
TOKEN = os.environ.get('AGENT_TOKEN')
BASE_DIR = Path(os.environ.get('OPENVPN_DIR', '/etc/openvpn/primevpn'))
PKI_DIR = Path(os.environ.get('OPENVPN_PKI', '/etc/openvpn/pki'))
CLIENTS_DIR = BASE_DIR / 'clients'
SERVER_CONFIG = BASE_DIR / 'server.conf'
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$')
EASYRSA = os.environ.get('EASYRSA_BIN', '/usr/share/easy-rsa/easyrsa')


def require_auth(creds: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)]) -> None:
    if not TOKEN or creds.credentials != TOKEN:
        raise HTTPException(status_code=401, detail='Invalid token')


Auth = Annotated[None, Depends(require_auth)]


class ServerConfig(BaseModel):
    port: int = Field(default=1194, ge=1, le=65535)
    protocol: str = Field(default='udp')
    network: str = Field(default='10.9.0.0/24')
    endpoint: str = Field(min_length=1, max_length=255)


class ClientRequest(BaseModel):
    name: str = Field(min_length=1, max_length=32)


def _run(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)


def _validate_name(name: str) -> str:
    if not NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail='Invalid client name')
    return name


def _ensure_pki() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
    if (PKI_DIR / 'ca.crt').is_file() and (PKI_DIR / 'private' / 'server.key').is_file():
        return
    if not (PKI_DIR / 'index.txt').exists():
        result = _run([EASYRSA, 'init-pki'], cwd=PKI_DIR.parent)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail='Failed to initialize OpenVPN PKI')
    if not (PKI_DIR / 'ca.crt').is_file():
        result = _run([EASYRSA, '--batch', 'build-ca', 'nopass'], cwd=PKI_DIR.parent)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail='Failed to create OpenVPN CA')
    if not (PKI_DIR / 'issued' / 'server.crt').is_file():
        result = _run([EASYRSA, '--batch', 'build-server-full', 'server', 'nopass'], cwd=PKI_DIR.parent)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail='Failed to create OpenVPN server certificate')
    if not (PKI_DIR / 'dh.pem').is_file():
        result = _run([EASYRSA, gen := 'gen-dh'], cwd=PKI_DIR.parent)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f'Failed to generate OpenVPN DH parameters: {gen}')
    if not (PKI_DIR / 'crl.pem').is_file():
        result = _run([EASYRSA, 'gen-crl'], cwd=PKI_DIR.parent)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail='Failed to generate OpenVPN CRL')


def _write_server_config(cfg: ServerConfig) -> None:
    network_ip, prefix = cfg.network.split('/', 1) if '/' in cfg.network else ('10.9.0.0', '24')
    if prefix not in {'8', '16', '24'} or not network_ip.startswith('10.'):
        raise HTTPException(status_code=400, detail='OpenVPN network must be a private 10.x /8, /16 or /24 network')
    _ensure_pki()
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    SERVER_CONFIG.write_text(
        f'port {cfg.port}\nproto {cfg.protocol}\ndev tun\n'
        f'server {network_ip} {prefix}\n'
        'topology subnet\n'
        f'ca {PKI_DIR}/ca.crt\n'
        f'cert {PKI_DIR}/issued/server.crt\n'
        f'key {PKI_DIR}/private/server.key\n'
        f'dh {PKI_DIR}/dh.pem\n'
        f'crl-verify {PKI_DIR}/crl.pem\n'
        'keepalive 10 60\npersist-key\npersist-tun\n'
        'user nobody\ngroup nogroup\n'
        'client-to-client\n'
        f'status {BASE_DIR}/status.log 10\nverb 3\n'
    )
    (BASE_DIR / 'endpoint').write_text(cfg.endpoint)


@router.get('/status')
def status(_: Auth):
    result = _run(['supervisorctl', 'status', 'openvpn'])
    running = result.returncode == 0 and 'RUNNING' in result.stdout
    return {'status': 'running' if running else 'stopped', 'configured': SERVER_CONFIG.is_file()}


@router.put('/server')
def configure_server(cfg: ServerConfig, _: Auth):
    if cfg.protocol not in {'udp', 'tcp-server'}:
        raise HTTPException(status_code=400, detail='protocol must be udp or tcp-server')
    _write_server_config(cfg)
    result = _run(['supervisorctl', 'restart', 'openvpn'])
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail='OpenVPN server failed to restart')
    return {'status': 'configured', 'port': cfg.port, 'protocol': cfg.protocol, 'network': cfg.network}


@router.post('/clients')
def create_client(req: ClientRequest, _: Auth):
    name = _validate_name(req.name)
    _ensure_pki()
    client_dir = CLIENTS_DIR / name
    if client_dir.exists():
        raise HTTPException(status_code=409, detail='OpenVPN client already exists')
    result = _run([EASYRSA, '--batch', 'build-client-full', name, 'nopass'], cwd=PKI_DIR.parent)
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail='Failed to create OpenVPN client certificate')
    client_dir.mkdir(parents=True)
    endpoint = (BASE_DIR / 'endpoint').read_text().strip() if (BASE_DIR / 'endpoint').is_file() else 'REPLACE_WITH_NODE_HOST:1194'
    ca = (PKI_DIR / 'ca.crt').read_text()
    crt = (PKI_DIR / 'issued' / f'{name}.crt').read_text()
    key = (PKI_DIR / 'private' / f'{name}.key').read_text()
    config = (
        'client\ndev tun\nproto udp\nremote ' + endpoint + '\n'
        'nobind\npersist-key\npersist-tun\nremote-cert-tls server\nverb 3\n'
        '<ca>\n' + ca + '</ca>\n<cert>\n' + crt + '</cert>\n<key>\n' + key + '</key>\n'
    )
    (client_dir / 'client.ovpn').write_text(config)
    return {'name': name, 'config_path': str(client_dir / 'client.ovpn')}


@router.get('/clients')
def list_clients(_: Auth):
    return {'clients': sorted(p.name for p in CLIENTS_DIR.iterdir() if p.is_dir())} if CLIENTS_DIR.exists() else {'clients': []}


@router.get('/clients/{name}/config')
def client_config(name: str, _: Auth):
    name = _validate_name(name)
    path = CLIENTS_DIR / name / 'client.ovpn'
    if not path.is_file():
        raise HTTPException(status_code=404, detail='OpenVPN client not found')
    return PlainTextResponse(path.read_text(), media_type='application/x-openvpn-profile')


@router.delete('/clients/{name}')
def revoke_client(name: str, _: Auth):
    name = _validate_name(name)
    result = _run([EASYRSA, '--batch', 'revoke', name], cwd=PKI_DIR.parent)
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail='Failed to revoke OpenVPN client')
    _run([EASYRSA, 'gen-crl'], cwd=PKI_DIR.parent)
    client_dir = CLIENTS_DIR / name
    if client_dir.exists():
        import shutil
        shutil.rmtree(client_dir)
    return {'status': 'revoked', 'name': name}
