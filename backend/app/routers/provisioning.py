from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pathlib import Path
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from ..db import get_db, set_platform_context
from ..deps import current_admin, require_tenant_manager
from ..models import Admin, Node, ProvisioningTask, NodeState
from ..services.reconcile import desired_node_state
from ..security import new_bootstrap_token, hash_token, create_agent_token, decode_agent_token
from ..config import settings

router = APIRouter()

INSTALL_SCRIPT = r"""#!/usr/bin/env bash
set -euo pipefail
BACKEND="${1:-}"
TASK_ID="${2:-}"
BOOTSTRAP="${3:-}"
PUBLIC_HOST="${4:-}"
# Railway converts plain-HTTP POST requests at the edge; bootstrap must use HTTPS.
if [[ "$BACKEND" == http://* ]]; then BACKEND="https://${BACKEND#http://}"; fi
if [ -z "$BACKEND" ] || [ -z "$TASK_ID" ] || [ -z "$BOOTSTRAP" ] || [ -z "$PUBLIC_HOST" ]; then
  echo "Usage: install.sh BACKEND_URL TASK_ID BOOTSTRAP_TOKEN PUBLIC_VPS_IP" >&2
  exit 2
fi
export DEBIAN_FRONTEND=noninteractive
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
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 11; }
command -v systemctl >/dev/null || { echo "systemd/systemctl is required" >&2; exit 12; }
# Make node networking survive reboots and keep the VPN forwarding baseline enabled.
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-primevpn.conf <<'SYSCTL'
net.ipv4.ip_forward=1
SYSCTL
sysctl --system >/dev/null 2>&1 || true
if command -v modprobe >/dev/null 2>&1; then modprobe wireguard >/dev/null 2>&1 || true; fi
# Avoid interactive iptables-persistent prompts during automated installs.
if command -v debconf-set-selections >/dev/null 2>&1; then
  printf '%s\n' 'iptables-persistent iptables-persistent/autosave_v4 boolean true' 'iptables-persistent iptables-persistent/autosave_v6 boolean true' | debconf-set-selections || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable netfilter-persistent >/dev/null 2>&1 || true
  systemctl enable iptables >/dev/null 2>&1 || true
fi
EXCHANGE="$(curl -fsS --max-time 20 -X POST "$BACKEND/api/v1/provisioning/bootstrap/$TASK_ID/exchange" -H 'Content-Type: application/json' --data "{\"token\":\"$BOOTSTRAP\"}")"
NODE_ID="$(printf '%s' "$EXCHANGE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["node_id"])')"
AGENT_TOKEN="$(printf '%s' "$EXCHANGE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["agent_token"])')"
VERIFY_KEY="$(printf '%s' "$EXCHANGE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["agent_verify_public_key"])')"
PORT=""
# Keep 443 available for VPN traffic. The Agent uses a dedicated TCP control port.
for CANDIDATE in 9443 10443 11443 12443 443; do
  if ! ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "([.:])${CANDIDATE}$"; then
    PORT="$CANDIDATE"
    break
  fi
done
[ -n "$PORT" ] || { echo "No free Agent TCP port found" >&2; exit 14; }
mkdir -p /opt/primevpn-node-agent /etc/primevpn
python3 -m venv /opt/primevpn-node-agent/venv
/opt/primevpn-node-agent/venv/bin/pip install --upgrade pip >/dev/null
RAW_BASE="$BACKEND/api/v1/provisioning/node-agent"
download_file() {
  local url="$1"
  local out="$2"
  local name="$(basename "$out")"
  echo "Downloading Node Agent: $name"
  curl --retry 5 --retry-delay 2 --retry-all-errors -fsSL --max-time 30 "$url" -o "$out"
}
download_file "$RAW_BASE/pyproject.toml" /opt/primevpn-node-agent/pyproject.toml
download_file "$RAW_BASE/app.py" /opt/primevpn-node-agent/app.py
download_file "$RAW_BASE/agent_security.py" /opt/primevpn-node-agent/agent_security.py
/opt/primevpn-node-agent/venv/bin/pip install "fastapi>=0.115,<1" "uvicorn[standard]>=0.30,<1" "pydantic>=2.9,<3" "PyJWT[crypto]>=2.10,<3" "cryptography>=43,<47" >/dev/null
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
openssl req -x509 -newkey ed25519 -nodes -days 3650 -keyout /etc/primevpn/agent.key -out /etc/primevpn/agent.crt -subj "/CN=$PUBLIC_HOST" -addext "$SAN" >/dev/null 2>&1
chmod 600 /etc/primevpn/agent.key
cat > /etc/systemd/system/primevpn-node-agent.service <<EOF
[Unit]
Description=PRIMEVPN Node Agent
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=/opt/primevpn-node-agent
EnvironmentFile=/etc/primevpn/agent.env
ExecStart=/opt/primevpn-node-agent/venv/bin/uvicorn app:app --host 0.0.0.0 --port ${PORT} --ssl-keyfile /etc/primevpn/agent.key --ssl-certfile /etc/primevpn/agent.crt
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable primevpn-node-agent.service >/dev/null
BASE="/opt/primevpn-node-agent"
cat > /usr/local/sbin/primevpn-node-refresh <<EOF
#!/usr/bin/env bash
set -euo pipefail
BACKEND="$BACKEND"
BASE="/opt/primevpn-node-agent"
TMP="\${BASE}/.refresh"
mkdir -p "\$TMP"
changed=0
for name in pyproject.toml app.py agent_security.py; do
  curl --retry 3 --retry-all-errors -fsSL --max-time 30 "\$BACKEND/api/v1/provisioning/node-agent/\$name" -o "\$TMP/\$name"
  if ! cmp -s "\$TMP/\$name" "\$BASE/\$name"; then changed=1; fi
done
if [ "\$changed" -eq 1 ]; then
  cp "\$TMP/pyproject.toml" "\$BASE/pyproject.toml"
  cp "\$TMP/app.py" "\$BASE/app.py"
  cp "\$TMP/agent_security.py" "\$BASE/agent_security.py"
  "\$BASE/venv/bin/pip" install --no-cache-dir "fastapi>=0.115,<1" "uvicorn[standard]>=0.30,<1" "pydantic>=2.9,<3" "PyJWT[crypto]>=2.10,<3" "cryptography>=43,<47" >/dev/null
  systemctl restart primevpn-node-agent.service
fi
rm -rf "\$TMP"
EOF
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
systemctl enable --now primevpn-node-refresh.timer
systemctl restart primevpn-node-agent.service
sleep 2
curl -kfsS --max-time 5 "https://127.0.0.1:$PORT/healthz" >/dev/null
# Open the Agent control port in every firewall layer we can manage locally.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q active; then ufw allow "$PORT/tcp" >/dev/null; fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null; firewall-cmd --reload >/dev/null; fi
if command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT
fi
if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1 || true; fi
AGENT_URL="https://$PUBLIC_HOST:$PORT"
PREFLIGHT="$(curl -kfsS --max-time 10 "https://127.0.0.1:$PORT/diagnostics/preflight" -H "X-Agent-Token: $AGENT_TOKEN")"
printf '%s' "$PREFLIGHT" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("ready") is True, " | ".join(x.get("name")+": "+x.get("detail","") for x in d.get("issues",[]))' || {
  echo "NODE PREFLIGHT FAILED"
  printf '%s\n' "$PREFLIGHT"
  echo "The node was NOT registered as READY."
  echo "Fix the reported checks and rerun this same installer command."
  exit 30
}
echo "NODE PREFLIGHT: PASS"
printf '%s\n' "$PREFLIGHT" | python3 -m json.tool 2>/dev/null || true

HEALTH="$(curl -kfsS --max-time 10 "https://127.0.0.1:$PORT/health" -H "X-Agent-Token: $AGENT_TOKEN")"
printf '%s' "$HEALTH" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("status")=="READY"; assert d.get("capabilities",{}).get("wireguard") is True; assert d.get("capabilities",{}).get("openvpn") is True' >/dev/null
CAPABILITIES="$(printf '%s' "$HEALTH" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin).get("capabilities") or {},separators=(",",":")))')"
REG_BODY="$(python3 -c 'import json,sys; print(json.dumps({"agent_url":sys.argv[1],"version":"100.0.5","capabilities":json.loads(sys.argv[2])},separators=(",",":")))' "$AGENT_URL" "$CAPABILITIES")"
curl -kfsS --max-time 20 -X POST "$BACKEND/api/v1/provisioning/$NODE_ID/register" -H "Authorization: Bearer $AGENT_TOKEN" -H 'Content-Type: application/json' --data "$REG_BODY" >/dev/null
echo "PRIMEVPN Node installed successfully and passed local preflight."
echo "Node ID: $NODE_ID"
echo "Agent: $AGENT_URL"
echo "Local checks: WireGuard=$(command -v wg >/dev/null && echo OK || echo MISSING) OpenVPN=$(command -v openvpn >/dev/null && echo OK || echo MISSING)"
echo "Firewall: managed locally; cloud/provider firewall may still require UDP/TCP rules in its control panel"
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
async def register_agent(node_id: str, body: AgentRegistration, request: Request, db: Session = Depends(get_db)):
    token = request.headers.get("Authorization", "")
    if not token.lower().startswith("bearer "): raise HTTPException(401, "Agent token required")
    try: claims = decode_agent_token(token[7:].strip())
    except Exception: raise HTTPException(401, "Invalid agent token")
    if claims.get("type") != "node_access" or claims.get("sub") != node_id: raise HTTPException(403, "Agent identity mismatch")
    node = db.query(Node).filter(Node.id == node_id, Node.tenant_id == claims.get("tenant_id")).first()
    if not node: raise HTTPException(404, "Node not found")
    import json
    node.agent_url = body.agent_url
    node.agent_version = body.version
    node.capabilities = json.dumps(body.capabilities or {}, separators=(",", ":"))
    node.state = NodeState.ready
    node.last_seen_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "READY", "node_id": node.id}
