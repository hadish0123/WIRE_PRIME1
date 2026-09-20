#!/usr/bin/env bash
set -euo pipefail
: "${PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY:?Set PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY to the Control Plane Ed25519 public PEM}"
install -d -m 0700 /etc/primevpn /opt/primevpn-agent /run/primevpn
cp -a . /opt/primevpn-agent/
apt-get update
apt-get install -y python3 python3-venv python3-pip wireguard-tools openvpn
if command -v awg >/dev/null 2>&1; then echo "AmneziaWG tools detected"; else echo "AmneziaWG tools not installed; install awg/awg-quick for AmneziaWG support"; fi
python3 -m venv /opt/primevpn-agent/.venv
/opt/primevpn-agent/.venv/bin/pip install --upgrade pip
/opt/primevpn-agent/.venv/bin/pip install .
printf '%s\n' "PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY=$PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY" > /etc/primevpn/agent.env
chmod 0600 /etc/primevpn/agent.env
cp primevpn-agent.service /etc/systemd/system/primevpn-agent.service
systemctl daemon-reload
systemctl enable --now primevpn-agent
systemctl --no-pager --full status primevpn-agent
