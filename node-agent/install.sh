#!/usr/bin/env bash
set -euo pipefail
: "${PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY:?Set PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY to the Control Plane Ed25519 public PEM}"
: "${PRIMEVPN_NODE_ID:?Set PRIMEVPN_NODE_ID to the PRIMEVPN Node UUID}"
install -d -m 0700 /etc/primevpn /opt/primevpn-agent /run/primevpn
cp -a . /opt/primevpn-agent/
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip wireguard-tools openvpn software-properties-common python3-launchpadlib gnupg2 dkms build-essential "linux-headers-$(uname -r)"
if ! command -v awg >/dev/null 2>&1 || ! command -v awg-quick >/dev/null 2>&1; then
  add-apt-repository -y ppa:amnezia/ppa
  apt-get update
  apt-get install -y amneziawg
fi
modprobe amneziawg >/dev/null 2>&1 || true
command -v awg >/dev/null 2>&1 && command -v awg-quick >/dev/null 2>&1 || { echo "AmneziaWG installation failed" >&2; exit 15; }
python3 -m venv /opt/primevpn-agent/.venv
/opt/primevpn-agent/.venv/bin/pip install --upgrade pip
/opt/primevpn-agent/.venv/bin/pip install .
printf "%s\n" "$PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY" > /etc/primevpn/control-agent-public.pem
chmod 0600 /etc/primevpn/control-agent-public.pem
printf '%s\n' "PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY_FILE=/etc/primevpn/control-agent-public.pem" "PRIMEVPN_NODE_ID=$PRIMEVPN_NODE_ID" > /etc/primevpn/agent.env
chmod 0600 /etc/primevpn/agent.env
cp primevpn-agent.service /etc/systemd/system/primevpn-agent.service
systemctl daemon-reload
systemctl enable --now primevpn-agent
systemctl --no-pager --full status primevpn-agent
