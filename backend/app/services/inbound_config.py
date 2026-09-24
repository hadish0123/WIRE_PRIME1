from __future__ import annotations
import ipaddress
from datetime import datetime, timezone
from sqlalchemy import or_
from ..models import Inbound, InboundWireGuard, InboundOpenVPN, Node, Protocol, Client, ClientCredential, Device, ResourceState
from ..security import decrypt_secret
from .credentials import wg_public_key

def render_inbound(inbound:Inbound,node:Node,db):
    if inbound.protocol in {Protocol.wireguard,Protocol.amneziawg}:
        wg=db.query(InboundWireGuard).filter(InboundWireGuard.inbound_id==inbound.id).first()
        if not wg or not wg.server_private_key_encrypted:
            raise RuntimeError("WireGuard server keys are not initialized")
        private=decrypt_secret(wg.server_private_key_encrypted)
        derived_public=wg_public_key(private)
        # The private key is authoritative; repair stale DB public-key metadata.
        if wg.server_public_key != derived_public:
            wg.server_public_key=derived_public
        lines=[
            "[Interface]",
            f"Address = {inbound.address}",
            f"ListenPort = {inbound.listen_port}",
            f"PrivateKey = {private}",
        ]
        if inbound.mtu: lines.append(f"MTU = {inbound.mtu}")
        if inbound.protocol==Protocol.amneziawg:
            lines += [f"Jc = {wg.amnezia_junk or 7}",f"Jmin = {wg.amnezia_init or 8}",f"Jmax = {wg.amnezia_response or 80}",f"S1 = {wg.amnezia_s1}",f"S2 = {wg.amnezia_s2}",f"S3 = {wg.amnezia_s3}",f"S4 = {wg.amnezia_s4}",f"H1 = {wg.amnezia_h1}",f"H2 = {wg.amnezia_h2}",f"H3 = {wg.amnezia_h3}",f"H4 = {wg.amnezia_h4}"]
        now=datetime.now(timezone.utc)
        peers=(db.query(ClientCredential,Device,Client)
               .join(Client,Client.id==ClientCredential.client_id)
               .outerjoin(Device,Device.id==ClientCredential.device_id)
               .filter(Client.inbound_id==inbound.id,Client.tenant_id==inbound.tenant_id,
                       Client.status==ResourceState.active,ClientCredential.revoked_at.is_(None),
                       or_(Client.expires_at.is_(None),Client.expires_at>now),
                       or_(ClientCredential.expires_at.is_(None),ClientCredential.expires_at>now))
               .order_by(ClientCredential.id).all())
        for credential,device,client in peers:
            address=device.assigned_address if device and device.assigned_address else client.assigned_address
            peer_ip=ipaddress.ip_interface(address).ip
            if peer_ip not in ipaddress.ip_network(inbound.network,strict=False) or peer_ip==ipaddress.ip_interface(inbound.address).ip:
                raise RuntimeError("Client address is outside the inbound network or equals the server address")
            lines += ["","[Peer]",f"PublicKey = {credential.public_identifier}",f"AllowedIPs = {peer_ip}/32"]
        return {"protocol":inbound.protocol.value,"interface":inbound.interface,"config":"\n".join(lines)+"\n","files":{}}
    ov=db.query(InboundOpenVPN).filter(InboundOpenVPN.inbound_id==inbound.id).first()
    if not ov or not ov.server_key_encrypted or not ov.ca_pem or not ov.server_cert_pem or not ov.tls_crypt_key_encrypted:
        raise RuntimeError("OpenVPN server credentials are not initialized")
    key=decrypt_secret(ov.server_key_encrypted)
    tls=decrypt_secret(ov.tls_crypt_key_encrypted)
    crl=ov.crl_pem or ""
    config=f"""port {inbound.listen_port}
proto {ov.transport}
dev {inbound.interface}
server {ov.server_network.split('/')[0]} {inbound.network.split('/')[1] if '/' in inbound.network else '24'}
topology subnet
persist-key
persist-tun
keepalive 10 120
user nobody
group nogroup
tls-version-min {ov.tls_min}
data-ciphers {ov.cipher_policy}
remote-cert-tls client
status /run/primevpn/{inbound.interface}.status 10
verb 3
<ca>
{ov.ca_pem}</ca>
<cert>
{ov.server_cert_pem}</cert>
<key>
{key}</key>
<tls-crypt>
{tls}</tls-crypt>
"""
    files={"crl.pem":crl} if crl else {}
    if crl: config += f"crl-verify /etc/primevpn/{inbound.interface}.crl.pem\n"
    return {"protocol":"openvpn","interface":inbound.interface,"config":config,"files":files}
