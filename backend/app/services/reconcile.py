import json
from sqlalchemy.orm import Session
from ..models import Node,Inbound,Client,ClientCredential,Device,InboundWireGuard,InboundOpenVPN,Protocol,NodeState
from ..security import decrypt_secret

def _wg_config(node,inbound,db):
    cfg=db.query(InboundWireGuard).filter(InboundWireGuard.inbound_id==inbound.id).first()
    if not cfg or not cfg.server_private_key_encrypted:
        return None
    lines=[
        "[Interface]",
        f"PrivateKey = {decrypt_secret(cfg.server_private_key_encrypted)}",
        f"Address = {inbound.address}",
        f"ListenPort = {inbound.listen_port}",
    ]
    if inbound.mtu: lines.append(f"MTU = {inbound.mtu}")
    if inbound.protocol==Protocol.amneziawg:
        lines += [
            f"Jc = {cfg.amnezia_junk or 7}",
            f"Jmin = {cfg.amnezia_init or 8}",
            f"Jmax = {cfg.amnezia_response or 80}",
            f"S1 = {cfg.amnezia_s1}",
            f"S2 = {cfg.amnezia_s2}",
            f"S3 = {cfg.amnezia_s3}",
            f"S4 = {cfg.amnezia_s4}",
            f"H1 = {cfg.amnezia_h1}",
            f"H2 = {cfg.amnezia_h2}",
            f"H3 = {cfg.amnezia_h3}",
            f"H4 = {cfg.amnezia_h4}",
        ]
    for client in db.query(Client).filter(Client.inbound_id==inbound.id,Client.tenant_id==node.tenant_id,Client.status=="ACTIVE").all():
        cred=db.query(ClientCredential).filter(ClientCredential.client_id==client.id,ClientCredential.revoked_at.is_(None)).order_by(ClientCredential.created_at.desc()).all()
        for credential in cred:
            device=db.query(Device).filter(Device.id==credential.device_id,Device.client_id==client.id).first() if credential.device_id else None
            allowed=device.assigned_address if device and device.assigned_address else client.assigned_address
            lines += ["","[Peer]",f"PublicKey = {credential.public_identifier}",f"AllowedIPs = {allowed}"]
    return "\n".join(lines)+"\n"

def _openvpn_config(node,inbound,db):
    cfg=db.query(InboundOpenVPN).filter(InboundOpenVPN.inbound_id==inbound.id).first()
    if not cfg or not cfg.ca_pem or not cfg.server_cert_pem or not cfg.server_key_encrypted or not cfg.tls_crypt_key_encrypted:
        return None
    lines=[
        "port "+str(inbound.listen_port),
        "proto "+cfg.transport,
        "dev "+inbound.interface,
        "topology subnet",
        "server "+cfg.server_network,
        "ca /etc/primevpn/"+inbound.interface+".ca.pem",
        "cert /etc/primevpn/"+inbound.interface+".server.pem",
        "key /etc/primevpn/"+inbound.interface+".server.key",
        "tls-server",
        "tls-version-min "+cfg.tls_min,
        "tls-crypt /etc/primevpn/"+inbound.interface+".tls.key",
        "data-ciphers "+cfg.cipher_policy,
        "keepalive 10 60",
        "persist-key",
        "persist-tun",
        "user nobody",
        "group nogroup",
        "status /run/primevpn/"+inbound.interface+".status 10",
        "crl-verify /etc/primevpn/"+inbound.interface+".crl.pem",
    ]
    payload={"config":"\n".join(lines)+"\n","files":{
        "ca.pem":cfg.ca_pem,
        "server.pem":cfg.server_cert_pem,
        "server.key":decrypt_secret(cfg.server_key_encrypted),
        "tls.key":decrypt_secret(cfg.tls_crypt_key_encrypted),
        "crl.pem":cfg.crl_pem or "",
    }}
    return payload

def desired_node_state(db:Session,node:Node):
    inbounds=db.query(Inbound).filter(Inbound.node_id==node.id,Inbound.tenant_id==node.tenant_id).all()
    result=[]
    for i in inbounds:
        item={"id":i.id,"protocol":i.protocol.value,"interface":i.interface,"listen_port":i.listen_port,"desired_state":i.desired_state,"enabled":i.enabled}
        if i.enabled and i.desired_state=="ACTIVE":
            if i.protocol in {Protocol.wireguard,Protocol.amneziawg}: item["config"]=_wg_config(node,i,db)
            else: item["openvpn"]=_openvpn_config(node,i,db)
        result.append(item)
    return {"node_id":node.id,"state":node.state.value,"inbounds":result}

def reconcile_node(db,node,current=None):
    desired=desired_node_state(db,node)
    return {"changed":desired!=current,"desired":desired,"current":current}

def sync_node(db,node,agent_client):
    health=agent_client.call(node,"GET","health")
    caps=health.get("capabilities",{})
    node.capabilities=json.dumps(caps,separators=(",",":"))
    node.agent_version=health.get("version")
    node.last_seen_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    if node.state in {NodeState.discovered,NodeState.authenticating,NodeState.installing,NodeState.configuring,NodeState.health_check,NodeState.syncing,NodeState.degraded,NodeState.offline}:
        node.state=NodeState.syncing
    desired=desired_node_state(db,node)
    for item in desired["inbounds"]:
        if not item.get("enabled") or item.get("desired_state")!="ACTIVE":
            agent_client.remove(node,item["protocol"],item["interface"])
            continue
        if not caps.get(item["protocol"],False):
            raise RuntimeError(f"Node lacks required capability: {item['protocol']}")
        if item["protocol"] in {"wireguard","amneziawg"}:
            if not item.get("config"): raise RuntimeError(f"Missing {item['protocol']} configuration for {item['interface']}")
            agent_client.call(node,"POST","apply",{"protocol":item["protocol"],"interface":item["interface"],"config":item["config"]})
        elif item["protocol"]=="openvpn":
            if not item.get("openvpn"): raise RuntimeError(f"Missing OpenVPN configuration for {item['interface']}")
            agent_client.apply_openvpn(node,item["interface"],item["openvpn"])
    node.state=NodeState.ready
    return desired
