from __future__ import annotations
import asyncssh
import httpx
import shlex

AGENT_REF="2c7854ee186a14dce3d307e2756b62d00b78d90d"
RAW_BASE=f"https://raw.githubusercontent.com/hadish0123/WIRE_PRIME1/{AGENT_REF}/node-agent"

class SSHProvisionError(RuntimeError):
    pass

def _q(v:str)->str:
    return shlex.quote(v)

async def install_node_agent(host:str,port:int,username:str,password:str,node_id:str,verify_key:str)->dict:
    if not host or any(c in host for c in "\n\r"):
        raise SSHProvisionError("Invalid server address")
    script=f'''set -eu
export DEBIAN_FRONTEND=noninteractive

if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip curl openssl iproute2 wireguard-tools openvpn
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y python3 python3-pip curl openssl iproute2 wireguard-tools openvpn
elif command -v yum >/dev/null 2>&1; then
  yum install -y python3 python3-pip curl openssl iproute2 wireguard-tools openvpn
else
  echo "Unsupported Linux distribution" >&2
  exit 20
fi

mkdir -p /opt/primevpn-node-agent /etc/primevpn
python3 -m venv /opt/primevpn-node-agent/venv
/opt/primevpn-node-agent/venv/bin/pip install --upgrade pip
curl -fsSL {_q(RAW_BASE+"/pyproject.toml")} -o /opt/primevpn-node-agent/pyproject.toml
curl -fsSL {_q(RAW_BASE+"/app.py")} -o /opt/primevpn-node-agent/app.py
curl -fsSL {_q(RAW_BASE+"/agent_security.py")} -o /opt/primevpn-node-agent/agent_security.py
/opt/primevpn-node-agent/venv/bin/pip install --no-cache-dir fastapi 'uvicorn[standard]' pydantic 'PyJWT[crypto]' cryptography

PORT=""
for CANDIDATE in 443 9443 10443 11443 12443; do
  if ! ss -ltnH 2>/dev/null | awk '{{print $4}}' | grep -qE "([.:])$CANDIDATE$"; then
    PORT="$CANDIDATE"
    break
  fi
done
if [ -z "$PORT" ]; then
  echo "No free Agent TCP port found" >&2
  exit 21
fi

if printf '%s' {_q(host)} | grep -Eq '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'; then
  SAN="subjectAltName=IP:{_q(host)}"
else
  SAN="subjectAltName=DNS:{_q(host)}"
fi
openssl req -x509 -nodes -newkey ed25519 -days 825 \
  -keyout /etc/primevpn/agent.key -out /etc/primevpn/agent.crt \
  -subj {_q("/CN="+host)} -addext "$SAN"
chmod 600 /etc/primevpn/agent.key

cat > /etc/primevpn/agent.env <<EOF
PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY={_q(verify_key)}
PRIMEVPN_NODE_ID={_q(node_id)}
PORT=$PORT
EOF
chmod 600 /etc/primevpn/agent.env

cat > /etc/systemd/system/primevpn-node-agent.service <<EOF
[Unit]
Description=PRIMEVPN Node Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/primevpn-node-agent
EnvironmentFile=/etc/primevpn/agent.env
ExecStart=/opt/primevpn-node-agent/venv/bin/uvicorn app:app --host 0.0.0.0 --port ${{PORT}} --ssl-keyfile /etc/primevpn/agent.key --ssl-certfile /etc/primevpn/agent.crt
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now primevpn-node-agent.service

for i in $(seq 1 15); do
  if systemctl is-active --quiet primevpn-node-agent.service && curl -kfsS --max-time 3 "https://127.0.0.1:${{PORT}}/healthz" >/dev/null; then
    break
  fi
  if [ "$i" -eq 15 ]; then
    echo "Node Agent failed to start on port ${PORT}" >&2
    systemctl --no-pager --full status primevpn-node-agent.service >&2 || true
    journalctl --no-pager -u primevpn-node-agent.service -n 80 >&2 || true
    exit 22
  fi
  sleep 1
done

# Open the selected Agent port when a host firewall is enabled.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "${{PORT}}/tcp" >/dev/null
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="${{PORT}}/tcp" >/dev/null
  firewall-cmd --reload >/dev/null
fi

printf 'PORT=%s\\n' "${{PORT}}"
'''
    try:
        async with asyncssh.connect(host,port=port,username=username,password=password,known_hosts=None,login_timeout=20,connect_timeout=20) as conn:
            who=await conn.run("id -u",check=True)
            uid=who.stdout.strip()
            cmd="bash -s" if uid=="0" else "sudo -S -p '' bash -s"
            stdin=script if uid=="0" else password+"\n"+script
            result=await conn.run(cmd,input=stdin,check=False,timeout=600)
            if result.exit_status!=0:
                raise SSHProvisionError((result.stderr or result.stdout or "SSH installation failed")[-4000:])
            port_line=next((x for x in result.stdout.splitlines() if x.startswith("PORT=")),None)
            agent_port=int(port_line.split("=",1)[1]) if port_line else 443
            async with conn.start_sftp_client() as sftp:
                cert_data=await sftp.read("/etc/primevpn/agent.crt")
            cert_pem=cert_data.decode() if isinstance(cert_data,bytes) else cert_data
            return {"agent_port":agent_port,"certificate":cert_pem}
    except asyncssh.Error as e:
        raise SSHProvisionError(f"SSH connection failed: {e}") from e

async def verify_agent(url:str,token:str)->dict:
    async with httpx.AsyncClient(verify=False,timeout=20) as client:
        r=await client.get(url.rstrip("/")+"/health",headers={"X-Agent-Token":token})
        if r.status_code>=400:
            raise SSHProvisionError(f"Node Agent health failed: HTTP {r.status_code} {r.text[:500]}")
        return r.json()
