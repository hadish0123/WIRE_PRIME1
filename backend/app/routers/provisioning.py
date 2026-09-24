from datetime import datetime, timezone, timedelta
import json
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pathlib import Path
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from ..db import get_db, set_platform_context
from ..deps import current_admin, require_tenant_manager
from ..models import Admin, Node, ProvisioningTask, NodeState, Inbound, InboundWireGuard, Client, Device, ClientCredential, ResourceState, Protocol
from ..services.reconcile import desired_node_state
from ..security import new_bootstrap_token, hash_token, create_agent_token, decode_agent_token, encrypt_secret, decrypt_secret
from ..config import settings
from ..services.credentials import wg_keypair
from ..services.agent_client import apply as apply_agent, call as agent_call
from ..services.inbound_config import render_inbound
from ..routers.credentials import issue as issue_client_credential

router = APIRouter()

INSTALL_SCRIPT = r"""#!/usr/bin/env bash
set -Eeuo pipefail

BACKEND="${1:-}"
TASK_ID="${2:-}"
BOOTSTRAP="${3:-}"
PUBLIC_HOST="${4:-}"

if [[ "$BACKEND" == http://* ]]; then BACKEND="https://${BACKEND#http://}"; fi
if [[ -z "$BACKEND" || -z "$TASK_ID" || -z "$BOOTSTRAP" || -z "$PUBLIC_HOST" ]]; then
  echo "Usage: install.sh BACKEND_URL TASK_ID BOOTSTRAP_TOKEN PUBLIC_VPS_IP" >&2
  exit 2
fi

export DEBIAN_FRONTEND=noninteractive
LOG="/var/log/primevpn-node-install.log"
exec > >(tee -a "$LOG") 2>&1

fail() {
  rc=$?
  echo
  echo "========== PRIMEVPN NODE INSTALL FAILED (exit $rc) =========="
  echo "Backend: $BACKEND"
  echo "Public host: $PUBLIC_HOST"
  echo "Agent port: ${PORT:-unset}"
  echo "Node ID: ${NODE_ID:-unset}"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl status primevpn-node-agent.service --no-pager -l 2>/dev/null || true
  fi
  if command -v ss >/dev/null 2>&1; then ss -ltnup 2>/dev/null || true; fi
  if command -v ip >/dev/null 2>&1; then ip route 2>/dev/null || true; fi
  exit "$rc"
}
trap fail ERR

echo "== PRIMEVPN NODE INSTALLER =="
echo "[1/10] Installing OS dependencies"

if command -v debconf-set-selections >/dev/null 2>&1; then
  printf '%s\n' \
    'iptables-persistent iptables-persistent/autosave_v4 boolean true' \
    'iptables-persistent iptables-persistent/autosave_v6 boolean true' | debconf-set-selections || true
fi

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y curl openssl ca-certificates python3 python3-venv python3-pip iproute2 iptables iptables-persistent wireguard-tools openvpn
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y curl openssl ca-certificates python3 python3-pip iproute iptables wireguard-tools openvpn iptables-services
elif command -v yum >/dev/null 2>&1; then
  yum install -y curl openssl ca-certificates python3 python3-pip iproute iptables wireguard-tools openvpn iptables-services
else
  echo "Unsupported Linux distribution: apt-get/dnf/yum not found" >&2
  exit 10
fi

for bin in curl openssl python3 systemctl ss ip iptables; do
  command -v "$bin" >/dev/null || { echo "Required command missing: $bin" >&2; exit 11; }
done
python3 -m venv --help >/dev/null 2>&1 || { echo "Python venv support is unavailable" >&2; exit 12; }

echo "[2/10] Enabling forwarding and kernel prerequisites"
mkdir -p /etc/sysctl.d /etc/primevpn /opt/primevpn-node-agent
cat > /etc/sysctl.d/99-primevpn.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
SYSCTL
sysctl --system >/dev/null 2>&1 || true
modprobe wireguard >/dev/null 2>&1 || true
command -v wg >/dev/null || { echo "WireGuard tools are missing" >&2; exit 13; }

echo "[3/10] Installing Node Agent"
PORT=""
for CANDIDATE in 9443 10443 11443 12443 443; do
  if ! ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "([.:])${CANDIDATE}$"; then
    PORT="$CANDIDATE"
    break
  fi
done
[ -n "$PORT" ] || { echo "No free TCP port for Node Agent" >&2; exit 14; }

BASE="/opt/primevpn-node-agent"
python3 -m venv "$BASE/venv"
"$BASE/venv/bin/pip" install --upgrade pip >/dev/null
RAW_BASE="$BACKEND/api/v1/provisioning/node-agent"

for name in pyproject.toml app.py agent_security.py; do
  echo "Downloading Node Agent: $name"
  curl --retry 5 --retry-delay 2 --retry-all-errors -fsSL --max-time 45 "$RAW_BASE/$name" -o "$BASE/$name"
  test -s "$BASE/$name"
done

"$BASE/venv/bin/pip" install --no-cache-dir \
  "fastapi>=0.115,<1" "uvicorn[standard]>=0.30,<1" "pydantic>=2.9,<3" \
  "PyJWT[crypto]>=2.10,<3" "cryptography>=43,<47" >/dev/null

echo "[4/10] Exchanging one-time bootstrap"
EXCHANGE="$(curl --retry 5 --retry-delay 2 --retry-all-errors -fsS --max-time 30 -X POST "$BACKEND/api/v1/provisioning/bootstrap/$TASK_ID/exchange" -H 'Content-Type: application/json' --data "{\"token\":\"$BOOTSTRAP\"}")"
NODE_ID="$(printf '%s' "$EXCHANGE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["node_id"])')"
AGENT_TOKEN="$(printf '%s' "$EXCHANGE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["agent_token"])')"
VERIFY_KEY="$(printf '%s' "$EXCHANGE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["agent_verify_public_key"])')"

printf '%s\n' "$VERIFY_KEY" > /etc/primevpn/agent-public.key
chmod 600 /etc/primevpn/agent-public.key

cat > /etc/primevpn/agent.env <<EOF
PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY_FILE=/etc/primevpn/agent-public.key
PRIMEVPN_NODE_ID=$NODE_ID
PORT=$PORT
EOF
chmod 600 /etc/primevpn/agent.env

if printf '%s' "$PUBLIC_HOST" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
  SAN="subjectAltName=IP:$PUBLIC_HOST"
else
  SAN="subjectAltName=DNS:$PUBLIC_HOST"
fi
openssl req -x509 -newkey ed25519 -nodes -days 3650 \
  -keyout /etc/primevpn/agent.key -out /etc/primevpn/agent.crt \
  -subj "/CN=$PUBLIC_HOST" -addext "$SAN" >/dev/null 2>&1
chmod 600 /etc/primevpn/agent.key

cat > /etc/systemd/system/primevpn-node-agent.service <<EOF
[Unit]
Description=PRIMEVPN Node Agent
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=$BASE
EnvironmentFile=/etc/primevpn/agent.env
ExecStart=$BASE/venv/bin/uvicorn app:app --host 0.0.0.0 --port $PORT --ssl-keyfile /etc/primevpn/agent.key --ssl-certfile /etc/primevpn/agent.crt
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable primevpn-node-agent.service >/dev/null
systemctl reset-failed primevpn-node-agent.service >/dev/null 2>&1 || true
systemctl restart primevpn-node-agent.service

echo "[5/10] Verifying local Node Agent"
AGENT_HEALTH_OK=0
for _ in $(seq 1 30); do
  if curl -kfsS --max-time 3 "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then AGENT_HEALTH_OK=1; break; fi
  sleep 1
done
[ "$AGENT_HEALTH_OK" -eq 1 ] || {
  echo "Node Agent did not become healthy"
  journalctl -u primevpn-node-agent.service -n 150 --no-pager || true
  exit 29
}

echo "[6/10] Configuring firewall and TCP control path"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q active; then
  ufw allow "$PORT/tcp" >/dev/null || true
  ufw allow 443/tcp >/dev/null || true
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null || true
  firewall-cmd --permanent --add-port=443/tcp >/dev/null || true
  firewall-cmd --reload >/dev/null || true
fi
iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT
iptables -C INPUT -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p tcp --dport 443 -j ACCEPT

# Remove stale PRIMEVPN control-path redirects left by previous installer runs.
# This is important when the agent port changes: multiple 443 -> agent-port rules
# can otherwise accumulate, and locally-originated HTTPS tests hit OUTPUT first.
for OLD_PORT in 9443 10443 11443 12443; do
  while iptables -t nat -C PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports "$OLD_PORT" >/dev/null 2>&1; do
    iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports "$OLD_PORT" >/dev/null 2>&1 || break
  done
  while iptables -t nat -C OUTPUT -p tcp -d "$PUBLIC_HOST" --dport 443 -j REDIRECT --to-ports "$OLD_PORT" >/dev/null 2>&1; do
    iptables -t nat -D OUTPUT -p tcp -d "$PUBLIC_HOST" --dport 443 -j REDIRECT --to-ports "$OLD_PORT" >/dev/null 2>&1 || break
  done
done

if [ "$PORT" != "443" ]; then
  iptables -t nat -C PREROUTING -p tcp -d "$PUBLIC_HOST" --dport 443 -j REDIRECT --to-ports "$PORT" >/dev/null 2>&1 || \
    iptables -t nat -I PREROUTING -p tcp -d "$PUBLIC_HOST" --dport 443 -j REDIRECT --to-ports "$PORT"
  iptables -t nat -C OUTPUT -p tcp -d "$PUBLIC_HOST" --dport 443 -j REDIRECT --to-ports "$PORT" >/dev/null 2>&1 || \
    iptables -t nat -I OUTPUT -p tcp -d "$PUBLIC_HOST" --dport 443 -j REDIRECT --to-ports "$PORT"
fi
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || true
fi

AGENT_URL="https://$PUBLIC_HOST:443"
echo "[7/10] Validating public control endpoint: $AGENT_URL"
PUBLIC_OK=0
for _ in $(seq 1 10); do
  if curl -kfsS --connect-timeout 3 --max-time 8 "$AGENT_URL/healthz" >/dev/null 2>&1; then PUBLIC_OK=1; break; fi
  sleep 1
done
if [ "$PUBLIC_OK" -ne 1 ]; then
  echo "Public Agent reachability test failed."
  echo "This normally means TCP/443 is blocked by the VPS/cloud firewall."
  ss -ltnp || true
  iptables -t nat -L PREROUTING -n -v || true
  iptables -t nat -L OUTPUT -n -v || true
  exit 31
fi

echo "[8/10] Running strict Node preflight"
PREFLIGHT="$(curl -kfsS --max-time 15 "https://127.0.0.1:$PORT/diagnostics/preflight" -H "X-Agent-Token: $AGENT_TOKEN")"
printf '%s' "$PREFLIGHT" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ready") is True, " | ".join((x.get("name","check")+": "+x.get("detail","")) for x in d.get("issues",[]))' || {
  echo "NODE PREFLIGHT FAILED"
  printf '%s\n' "$PREFLIGHT"
  exit 30
}
echo "NODE PREFLIGHT: PASS"

HEALTH="$(curl -kfsS --max-time 15 "https://127.0.0.1:$PORT/health" -H "X-Agent-Token: $AGENT_TOKEN")"
printf '%s' "$HEALTH" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("status")=="READY"; assert d.get("capabilities",{}).get("wireguard") is True' >/dev/null
CAPABILITIES="$(printf '%s' "$HEALTH" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin).get("capabilities") or {},separators=(",",":")))')"

echo "[9/10] Registering Node"
REG_BODY="$(python3 -c 'import json,sys; print(json.dumps({"agent_url":sys.argv[1],"version":"100.0.13","capabilities":json.loads(sys.argv[2])},separators=(",",":")))' "$AGENT_URL" "$CAPABILITIES")"
REG_TMP="$(mktemp)"
REG_CODE="$(curl -kS --max-time 60 -o "$REG_TMP" -w '%{http_code}' -X POST "$BACKEND/api/v1/provisioning/$NODE_ID/register" \
  -H "Authorization: Bearer $AGENT_TOKEN" -H 'Content-Type: application/json' --data "$REG_BODY" || true)"
if [ "$REG_CODE" != "200" ]; then
  echo "NODE REGISTRATION FAILED: HTTP $REG_CODE"
  echo "Registration response:"
  cat "$REG_TMP" 2>/dev/null || true
  echo
  echo "Node Agent runtime snapshot:"
  curl -kfsS --max-time 15 "https://127.0.0.1:$PORT/health" -H "X-Agent-Token: $AGENT_TOKEN" 2>/dev/null || true
  echo
  rm -f "$REG_TMP"
  exit 32
fi
rm -f "$REG_TMP"

echo "[10/10] Final runtime validation"
RUNTIME="$(curl -kfsS --max-time 15 "https://127.0.0.1:$PORT/health" -H "X-Agent-Token: $AGENT_TOKEN")"
printf '%s' "$RUNTIME" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("status")=="READY"; assert d.get("capabilities",{}).get("wireguard") is True' >/dev/null

cat > /usr/local/sbin/primevpn-node-refresh <<'REFRESH_EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
BACKEND="__BACKEND__"
BASE="/opt/primevpn-node-agent"
TMP="$BASE/.refresh"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT
changed=0
for name in pyproject.toml app.py agent_security.py; do
  curl --retry 3 --retry-all-errors -fsSL --max-time 45 "$BACKEND/api/v1/provisioning/node-agent/$name" -o "$TMP/$name"
  test -s "$TMP/$name"
  if ! cmp -s "$TMP/$name" "$BASE/$name"; then changed=1; fi
done
if [ "$changed" -eq 1 ]; then
  cp "$TMP/pyproject.toml" "$BASE/pyproject.toml"
  cp "$TMP/app.py" "$BASE/app.py"
  cp "$TMP/agent_security.py" "$BASE/agent_security.py"
  "$BASE/venv/bin/pip" install --no-cache-dir "fastapi>=0.115,<1" "uvicorn[standard]>=0.30,<1" "pydantic>=2.9,<3" "PyJWT[crypto]>=2.10,<3" "cryptography>=43,<47" >/dev/null
  systemctl restart primevpn-node-agent.service
fi
REFRESH_EOF
sed -i "s|__BACKEND__|$BACKEND|g" /usr/local/sbin/primevpn-node-refresh
chmod 700 /usr/local/sbin/primevpn-node-refresh
cat > /etc/systemd/system/primevpn-node-refresh.service <<'EOF'
[Unit]
Description=PRIMEVPN Node Agent updater
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/primevpn-node-refresh
EOF
cat > /etc/systemd/system/primevpn-node-refresh.timer <<'EOF'
[Unit]
Description=Keep PRIMEVPN Node Agent synchronized
[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now primevpn-node-refresh.timer >/dev/null

echo "PRIMEVPN Node installed successfully and passed local/public preflight."
echo "Node ID: $NODE_ID"
echo "Agent: $AGENT_URL"
echo "Local checks: WireGuard=$(command -v wg >/dev/null && echo OK || echo MISSING) OpenVPN=$(command -v openvpn >/dev/null && echo OK || echo MISSING)"
echo "Traffic validation: infrastructure READY; client traffic requires a real client handshake."
"""


class BootstrapExchange(BaseModel):
    token: str = Field(min_length=30, max_length=256)

@router.get("/install.sh", response_class=PlainTextResponse)
def install_script():
    return INSTALL_SCRIPT
@router.get("/node-agent/{filename}", response_class=PlainTextResponse)
def node_agent_file(filename: str):
    allowed = {"pyproject.toml", "app.py", "agent_security.py"}
    if filename not in allowed:
        raise HTTPException(404, "Node Agent file not found")
    path = Path(__file__).resolve().parents[1] / "node-agent" / filename
    if not path.is_file():
        raise HTTPException(404, "Node Agent file not found")
    return PlainTextResponse(path.read_text(encoding="utf-8"))


@router.get("/{node_id}/desired-state")
def desired(node_id: str, admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    n = db.query(Node).filter(Node.id == node_id, Node.tenant_id == admin.tenant_id).first()
    if not n: raise HTTPException(404, "Node not found")
    return desired_node_state(db, n)

@router.get("/{node_id}/traffic-diagnostics")
def traffic_diagnostics(node_id: str, admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    node=db.query(Node).filter(Node.id==node_id,Node.tenant_id==admin.tenant_id).first()
    if not node: raise HTTPException(404,"Node not found")
    inbound=db.query(Inbound).filter(Inbound.node_id==node.id,Inbound.tenant_id==node.tenant_id).order_by(Inbound.created_at.asc()).first()
    if not inbound: return {"status":"NO_INBOUND","reason":"No inbound exists on this node yet."}
    if inbound.protocol not in {Protocol.wireguard,Protocol.amneziawg}: return {"status":"UNSUPPORTED","reason":"Traffic diagnostics currently target the automatic WireGuard smoke test."}
    try:
        diag=agent_call(node,"GET",f"diagnostics/wireguard/{inbound.interface}/{inbound.listen_port}",None,15)
        peers=diag.get("peers") or []
        if not peers:
            return {"status":"NO_PEER","inbound_id":inbound.id,"reason":"Inbound is installed, but no WireGuard peer is installed. Create/issue a client credential."}
        active=[p for p in peers if int(p.get("last_handshake") or 0)>0]
        if not active:
            return {"status":"NO_HANDSHAKE","inbound_id":inbound.id,"peers":peers,"reason":"Peer is installed, but no client handshake has reached the Node. Check client activation, Endpoint IP/UDP port, and provider/cloud firewall UDP access."}
        node_host=str(node.address or "").strip("[]")
        def peer_host(peer):
            endpoint=str(peer.get("endpoint") or "")
            return endpoint.rsplit(":",1)[0].strip("[]") if ":" in endpoint else endpoint
        external=[p for p in active if peer_host(p) and peer_host(p)!=node_host]
        if not external:
            return {"status":"SELF_TEST_ONLY","inbound_id":inbound.id,"peer":active[0],"reason":"Observed WireGuard handshakes originated only from the Node public address itself. No external client handshake has been observed."}
        p=external[0]
        if int(p.get("bytes_received") or 0)==0 and int(p.get("bytes_sent") or 0)==0:
            return {"status":"HANDSHAKE_ONLY","inbound_id":inbound.id,"peer":p,"reason":"Handshake exists, but no client payload traffic has been observed yet. Open a website/ping from the client."}
        return {"status":"TRAFFIC_DETECTED","inbound_id":inbound.id,"peer":p,"reason":"An external WireGuard peer handshake and RX/TX traffic are being observed."}
    except Exception as exc:
        return {"status":"DIAGNOSTICS_UNAVAILABLE","inbound_id":inbound.id,"reason":str(exc)}

@router.get("/{node_id}/tasks")
def tasks(node_id: str, admin: Admin = Depends(current_admin), db: Session = Depends(get_db)):
    if not db.query(Node).filter(Node.id == node_id, Node.tenant_id == admin.tenant_id).first():
        raise HTTPException(404, "Node not found")
    return db.query(ProvisioningTask).filter(ProvisioningTask.node_id == node_id, ProvisioningTask.tenant_id == admin.tenant_id).order_by(ProvisioningTask.created_at.desc()).limit(100).all()

@router.post("/{node_id}/bootstrap")
def bootstrap(node_id: str, admin: Admin = Depends(require_tenant_manager), db: Session = Depends(get_db)):
    n = db.query(Node).filter(Node.id == node_id, Node.tenant_id == admin.tenant_id).first()
    if not n: raise HTTPException(404, "Node not found")
    raw, h = new_bootstrap_token()
    task = ProvisioningTask(tenant_id=admin.tenant_id, node_id=n.id, idempotency_key="bootstrap:" + raw, state=NodeState.authenticating.value, bootstrap_token_hash=h, bootstrap_expires_at=datetime.now(timezone.utc) + timedelta(minutes=15))
    db.add(task); n.state = NodeState.authenticating; db.commit()
    return {"task_id": task.id, "bootstrap_token": raw, "expires_at": task.bootstrap_expires_at}

@router.post("/bootstrap/{task_id}/exchange")
def exchange(task_id: str, body: BootstrapExchange, db: Session = Depends(get_db)):
    set_platform_context(db)
    task = db.query(ProvisioningTask).filter(ProvisioningTask.id == task_id).with_for_update().first()
    now = datetime.now(timezone.utc)
    if not task or not task.bootstrap_token_hash or not task.bootstrap_expires_at or task.bootstrap_expires_at <= now: raise HTTPException(401, "Bootstrap token expired")
    if hash_token(body.token) != task.bootstrap_token_hash: raise HTTPException(401, "Invalid bootstrap token")
    node = db.query(Node).filter(Node.id == task.node_id, Node.tenant_id == task.tenant_id).first()
    if not node: raise HTTPException(401, "Invalid bootstrap binding")
    task.bootstrap_token_hash = None; task.bootstrap_expires_at = None; task.state = NodeState.syncing.value; node.state = NodeState.syncing; db.commit()
    return {"node_id": node.id, "tenant_id": node.tenant_id, "agent_token": create_agent_token(node.id, node.tenant_id, ["read", "write"]), "agent_verify_public_key": settings.agent_verify_public_key, "expires_in": 600}

class AgentRegistration(BaseModel):
    agent_url: str = Field(min_length=10, max_length=512)
    version: str | None = Field(default=None, max_length=40)
    capabilities: dict = Field(default_factory=dict)

@router.post("/{node_id}/register")
def register_agent(node_id: str, body: AgentRegistration, request: Request, db: Session = Depends(get_db)):
    token = request.headers.get("Authorization", "")
    if not token.lower().startswith("bearer "): raise HTTPException(401, "Agent token required")
    try: claims = decode_agent_token(token[7:].strip())
    except Exception: raise HTTPException(401, "Invalid agent token")
    if claims.get("type") != "node_access" or claims.get("sub") != node_id: raise HTTPException(403, "Agent identity mismatch")
    from ..db import set_tenant_context
    set_tenant_context(db, claims.get("tenant_id"))
    node = db.query(Node).filter(Node.id == node_id, Node.tenant_id == claims.get("tenant_id")).first()
    if not node: raise HTTPException(404, "Node not found")
    import json
    node.agent_url = body.agent_url
    node.agent_version = body.version
    node.capabilities = json.dumps(body.capabilities or {}, separators=(",", ":"))
    try:
        health=agent_call(node,"GET","health",timeout=15)
        if not health.get("capabilities",{}).get("wireguard"):
            raise RuntimeError("WireGuard is unavailable on the new node")
    except Exception as exc:
        node.state=NodeState.provision_failed
        db.commit()
        raise HTTPException(502,f"Control plane cannot reach the Node Agent: {exc}")
    node.state = NodeState.ready
    node.last_seen_at = datetime.now(timezone.utc)
    db.commit()
    # Registration only establishes the control plane. Do not create test
    # inbounds/clients here: provisioning must remain Node -> Inbound -> Client,
    # and failed smoke tests must never leave committed test resources behind.
    return {"status":"READY","node_id":node.id,"auto_setup":{"created":False}}
