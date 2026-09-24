import ipaddress
import os
import sys

from app.db import SessionLocal, set_platform_context
from app.models import Client, ClientCredential, Device, Inbound, Node, Protocol
from app.services.agent_client import apply as apply_agent, call as agent_call
from app.services.inbound_config import render_inbound

NODE_ID = os.getenv("PRIMEVPN_WG_MIGRATE_NODE_ID", "").strip()
FROM_PORT = int(os.getenv("PRIMEVPN_WG_MIGRATE_FROM_PORT", "51820"))
TO_PORT = int(os.getenv("PRIMEVPN_WG_MIGRATE_TO_PORT", "443"))

def main():
    if not NODE_ID:
        print("WG_PORT_MIGRATION skipped: PRIMEVPN_WG_MIGRATE_NODE_ID is empty", flush=True)
        return 0

    db = SessionLocal()
    try:
        set_platform_context(db)
        node = db.query(Node).filter(Node.id == NODE_ID).first()
        if not node:
            raise RuntimeError("target node not found")

        matches = (
            db.query(Inbound)
            .filter(
                Inbound.node_id == NODE_ID,
                Inbound.protocol == Protocol.wireguard,
                Inbound.listen_port == FROM_PORT,
                Inbound.enabled.is_(True),
                Inbound.desired_state == "ACTIVE",
            )
            .all()
        )
        if len(matches) == 0:
            existing = (
                db.query(Inbound)
                .filter(
                    Inbound.node_id == NODE_ID,
                    Inbound.protocol == Protocol.wireguard,
                    Inbound.listen_port == TO_PORT,
                    Inbound.enabled.is_(True),
                    Inbound.desired_state == "ACTIVE",
                )
                .all()
            )
            if len(existing) == 1:
                print(f"WG_PORT_MIGRATION already complete inbound={existing[0].id} name={existing[0].name} port={TO_PORT}", flush=True)
                return 0
            raise RuntimeError(f"expected exactly one active WireGuard inbound on port {FROM_PORT}; found 0")
        if len(matches) != 1:
            raise RuntimeError(f"expected exactly one active WireGuard inbound on port {FROM_PORT}; found {len(matches)}")

        inbound = matches[0]
        collision = (
            db.query(Inbound)
            .filter(
                Inbound.node_id == NODE_ID,
                Inbound.listen_port == TO_PORT,
                Inbound.id != inbound.id,
            )
            .first()
        )
        if collision:
            raise RuntimeError(f"target port {TO_PORT} is already used by inbound {collision.id}")

        inbound.listen_port = TO_PORT
        db.flush()

        rendered = render_inbound(inbound, node, db)
        rows = (
            db.query(ClientCredential, Device)
            .join(Device, Device.id == ClientCredential.device_id)
            .join(Client, Client.id == ClientCredential.client_id)
            .filter(
                Client.inbound_id == inbound.id,
                Client.tenant_id == inbound.tenant_id,
                ClientCredential.revoked_at.is_(None),
            )
            .all()
        )
        peers = []
        for cred, dev in rows:
            if not dev.assigned_address:
                continue
            peer_ip = f"{ipaddress.ip_interface(dev.assigned_address).ip}/32"
            peers.extend(["", "[Peer]", f"PublicKey = {cred.public_identifier}", f"AllowedIPs = {peer_ip}"])

        full_config = rendered["config"].rstrip() + "\n" + "\n".join(peers) + "\n"
        apply_agent(node, rendered["protocol"], rendered["interface"], full_config, rendered.get("files"))

        diag = agent_call(node, "GET", f"diagnostics/wireguard/{inbound.interface}/{TO_PORT}", timeout=20)
        live_port = int(diag.get("live_port") or 0)
        iface_addr = str(diag.get("interface_addresses") or "")
        input_rules = diag.get("iptables_input_matches") or []
        peer_count = int(diag.get("peer_count") or 0)

        if live_port != TO_PORT:
            raise RuntimeError(f"live WireGuard port mismatch: expected {TO_PORT}, got {live_port}")
        if str(ipaddress.ip_interface(inbound.address)) not in iface_addr:
            raise RuntimeError("live WireGuard interface address mismatch")
        if peer_count < 1:
            raise RuntimeError("no WireGuard peers are present after migration")
        if not input_rules:
            raise RuntimeError(f"UDP/{TO_PORT} INPUT rule is missing")

        db.commit()
        print(
            f"WG_PORT_MIGRATION success inbound={inbound.id} name={inbound.name} "
            f"old_port={FROM_PORT} new_port={TO_PORT} peer_count={peer_count} "
            f"live_port={live_port} interface_address_ok=true udp_input_rule=true",
            flush=True,
        )
        return 0
    except Exception as exc:
        db.rollback()
        print(f"WG_PORT_MIGRATION failed: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        db.close()

if __name__ == "__main__":
    raise SystemExit(main())
