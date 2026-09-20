import ipaddress
import os
import re
import subprocess
import json
import threading
import time
from datetime import datetime, timezone
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
    traffic_bytes: int = Field(default=0, ge=0)
    expire_at: str | None = None


def _run(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)


def _validate_name(name: str) -> str:
    if not NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail='Invalid client name')
    return name



def _limits_path(name: str) -> Path:
    return CLIENTS_DIR / name / 'limits.json'

def _save_limits(name: str, traffic_bytes: int, expire_at: str | None) -> None:
    path = _limits_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({'traffic_bytes': traffic_bytes, 'expire_at': expire_at}, separators=(',', ':')))

def _parse_status_usage() -> dict[str, int]:
    path = BASE_DIR / 'status.log'
    if not path.is_file():
        return {}
    usage: dict[str, int] = {}
    try:
        for line in path.read_text(errors='ignore').splitlines():
            if not line.startswith('CLIENT_LIST,'):
                continue
            parts = line.split(',')
            if len(parts) >= 6:
                try:
                    usage[parts[1]] = int(parts[5]) + int(parts[6])
                except ValueError:
                    pass
    except OSError:
        pass
    return usage

def _enforce_limits_once() -> None:
    now = datetime.now(timezone.utc)
    for client_dir in CLIENTS_DIR.iterdir() if CLIENTS_DIR.exists() else []:
        if not client_dir.is_dir():
            continue
        limits = _limits_path(client_dir.name)
        if not limits.is_file():
            continue
        try:
            data = json.loads(limits.read_text())
        except (OSError, ValueError):
            continue
        expired = False
        if data.get('expire_at'):
            try:
                expired = datetime.fromisoformat(data['expire_at'].replace('Z', '+00:00')) <= now
            except ValueError:
                pass
        limit = int(data.get('traffic_bytes') or 0)
        used = _parse_status_usage().get(client_dir.name, 0)
        if expired or (limit > 0 and used >= limit):
            env = {**os.environ, 'EASYRSA_PKI': str(PKI_DIR)}
            result = subprocess.run([EASYRSA, '--batch', 'revoke', client_dir.name], cwd=PKI_DIR.parent, env=env, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                subprocess.run([EASYRSA, 'gen-crl'], cwd=PKI_DIR.parent, env=env, capture_output=True, text=True, check=False)
                subprocess.run(['supervisorctl', 'restart', 'openvpn'], capture_output=True, text=True, check=False)
                try:
                    limits.unlink()
                except OSError:
                    pass

def _limit_monitor() -> None:
    while True:
        try:
            _enforce_limits_once()
        except Exception:
            pass
        time.sleep(30)

threading.Thread(target=_limit_monitor, name='primevpn-openvpn-limits', daemon=True).start()

def _ensure_pki() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    PKI_DIR.parent.mkdir(parents=True, exist_ok=True)
    CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
    if (PKI_DIR / 'ca.crt').is_file() and (PKI_DIR / 'private' / 'server.key').is_file():
        return
    env = {**os.environ, 'EASYRSA_PKI': str(PKI_DIR)}
    if not (PKI_DIR / 'index.txt').exists():
        result = subprocess.run([EASYRSA, 'init-pki'], cwd=PKI_DIR.parent, env=env, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail='Failed to initialize OpenVPN PKI')
    if not (PKI_DIR / 'ca.crt').is_file():
        result = subprocess.run([EASYRSA, '--batch', 'build-ca', 'nopass'], cwd=PKI_DIR.parent, env=env, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail='Failed to create OpenVPN CA')
    if not (PKI_DIR / 'issued' / 'server.crt').is_file():
        result = subprocess.run([EASYRSA, '--batch', 'build-server-full', 'server', 'nopass'], cwd=PKI_DIR.parent, env=env, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail='Failed to create OpenVPN server certificate')
    if not (PKI_DIR / 'dh.pem').is_file():
        result = subprocess.run([EASYRSA, 'gen-dh'], cwd=PKI_DIR.parent, env=env, capture_output=True, text=True, check=False)
        gen = 'gen-dh'
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f'Failed to generate OpenVPN DH parameters: {gen}')
    if not (PKI_DIR / 'crl.pem').is_file():
        result = subprocess.run([EASYRSA, 'gen-crl'], cwd=PKI_DIR.parent, env=env, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail='Failed to generate OpenVPN CRL')


def _write_server_config(cfg: ServerConfig) -> None:
    try:
        network = ipaddress.ip_network(cfg.network, strict=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail='Invalid OpenVPN network') from exc
    if network.version != 4 or not network.is_private:
        raise HTTPException(status_code=400, detail='OpenVPN network must be a private IPv4 network')
    _ensure_pki()
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    netmask = str(network.netmask)
    SERVER_CONFIG.write_text(
        f'port {cfg.port}\nproto {cfg.protocol}\ndev tun\n'
        f'server {network.network_address} {netmask}\n'
        'topology subnet\n'
        f'ca {PKI_DIR}/ca.crt\n'
        f'cert {PKI_DIR}/issued/server.crt\n'
        f'key {PKI_DIR}/private/server.key\n'
        f'dh {PKI_DIR}/dh.pem\n'
        f'crl-verify {PKI_DIR}/crl.pem\n'
        'keepalive 10 60\npersist-key\npersist-tun\n'
        'user nobody\ngroup nogroup\n'
        'client-to-client\n'
        'tls-version-min 1.2\nauth SHA256\ncipher AES-256-GCM\ndata-ciphers AES-256-GCM:AES-128-GCM\n'
        f'status {BASE_DIR}/status.log 10\nverb 3\n'
    )
    (BASE_DIR / 'endpoint').write_text(cfg.endpoint)
    (BASE_DIR / 'server_meta.json').write_text(json.dumps({'port': cfg.port, 'protocol': cfg.protocol, 'endpoint': cfg.endpoint}, separators=(',', ':')))


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
    env = {**os.environ, 'EASYRSA_PKI': str(PKI_DIR)}
    result = subprocess.run([EASYRSA, '--batch', 'build-client-full', name, 'nopass'], cwd=PKI_DIR.parent, env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail='Failed to create OpenVPN client certificate')
    client_dir.mkdir(parents=True)
    meta = json.loads((BASE_DIR / 'server_meta.json').read_text()) if (BASE_DIR / 'server_meta.json').is_file() else {'protocol':'udp','endpoint':'REPLACE_WITH_NODE_HOST:1194'}
    endpoint = str(meta.get('endpoint') or 'REPLACE_WITH_NODE_HOST:1194')
    proto = str(meta.get('protocol') or 'udp')
    ca = (PKI_DIR / 'ca.crt').read_text()
    crt = (PKI_DIR / 'issued' / f'{name}.crt').read_text()
    key = (PKI_DIR / 'private' / f'{name}.key').read_text()
    config = (
        'client\ndev tun\nproto ' + proto + '\nremote ' + endpoint + '\n'
        'nobind\npersist-key\npersist-tun\nremote-cert-tls server\nauth SHA256\ncipher AES-256-GCM\ndata-ciphers AES-256-GCM:AES-128-GCM\nverb 3\n'
        '<ca>\n' + ca + '</ca>\n<cert>\n' + crt + '</cert>\n<key>\n' + key + '</key>\n'
    )
    (client_dir / 'client.ovpn').write_text(config)
    _save_limits(name, req.traffic_bytes, req.expire_at)
    return {'name': name, 'config_path': str(client_dir / 'client.ovpn'), 'traffic_bytes': req.traffic_bytes, 'expire_at': req.expire_at}


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
    env = {**os.environ, 'EASYRSA_PKI': str(PKI_DIR)}
    result = subprocess.run([EASYRSA, '--batch', 'revoke', name], cwd=PKI_DIR.parent, env=env, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise HTTPException(status_code=500, detail='Failed to revoke OpenVPN client')
    subprocess.run([EASYRSA, 'gen-crl'], cwd=PKI_DIR.parent, env=env, capture_output=True, text=True, check=False)
    client_dir = CLIENTS_DIR / name
    if client_dir.exists():
        import shutil
        shutil.rmtree(client_dir)
    return {'status': 'revoked', 'name': name}
