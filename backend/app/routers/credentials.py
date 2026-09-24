import json,ipaddress
from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_tenant_manager,can_access_client
from ..models import Admin,Client,Device,Inbound,InboundOpenVPN,InboundWireGuard,ClientCredential,ConfigArtifact,Protocol,Node,Quota,TrafficUsage
from ..security import encrypt_secret,decrypt_secret
from ..services.credentials import wg_keypair,wg_public_key,openvpn_ca,openvpn_server,openvpn_client,openvpn_tls_crypt_key,fingerprint
from ..services.config_artifacts import create_artifact
from ..services.inbound_config import render_inbound
from ..services.agent_client import apply as apply_agent
from ..services.openvpn_revoke import create_empty_crl
router=APIRouter()

def allocate_device_address(db,client):
 base=ipaddress.ip_interface(client.assigned_address)
 devices=db.query(Device).filter(Device.client_id==client.id,Device.assigned_address.isnot(None)).all()
 if not devices:return client.assigned_address
 used={client.assigned_address}
 for d in devices:used.add(d.assigned_address)
 candidates=list(base.network.hosts())
 if not candidates:raise HTTPException(409,"No usable addresses remain for this client network")
 for addr in candidates:
  value=f"{addr}/{base.network.prefixlen}"
  if value not in used:return value
 raise HTTPException(409,"No free device address remains")

@router.post("/{client_id}/credentials")
def issue(client_id:str,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 c=db.query(Client).filter(Client.id==client_id,Client.tenant_id==admin.tenant_id).first()
 if not c:raise HTTPException(404,"Client not found")
 now=__import__("datetime").datetime.now(__import__("datetime").timezone.utc)
 client_exp=c.expires_at
 if client_exp and client_exp.tzinfo is None:client_exp=client_exp.replace(tzinfo=__import__("datetime").timezone.utc)
 if c.status.value!="ACTIVE":raise HTTPException(409,"Client is not active")
 if client_exp and client_exp<=now:raise HTTPException(409,"Client has expired")
 q=db.query(Quota).filter(Quota.client_id==c.id,Quota.tenant_id==admin.tenant_id).first()
 if q:
  qexp=q.expires_at
  if qexp and qexp.tzinfo is None:qexp=qexp.replace(tzinfo=__import__("datetime").timezone.utc)
  used=int(db.query(__import__("sqlalchemy").func.coalesce(__import__("sqlalchemy").func.sum(TrafficUsage.bytes_in+TrafficUsage.bytes_out),0)).filter(TrafficUsage.client_id==c.id,TrafficUsage.tenant_id==admin.tenant_id).scalar() or 0)
  if qexp and qexp<=now:raise HTTPException(409,"Client quota has expired")
  if q.total_bytes is not None and used>=q.total_bytes:raise HTTPException(409,"Client traffic quota is exhausted")
  if q.max_devices is not None and db.query(Device).filter(Device.client_id==c.id,Device.tenant_id==admin.tenant_id).count()>=q.max_devices:raise HTTPException(409,"Maximum device limit reached")
 inbound=db.query(Inbound).filter(Inbound.id==c.inbound_id,Inbound.tenant_id==admin.tenant_id).first()
 if not inbound:raise HTTPException(404,"Inbound not found")
 node=db.query(Node).filter(Node.id==inbound.node_id,Node.tenant_id==admin.tenant_id).first()
 if not node:raise HTTPException(404,"Node not found")
 try:
  endpoint_ip=ipaddress.ip_address(node.address)
  if endpoint_ip.is_private or endpoint_ip.is_loopback or endpoint_ip.is_link_local or endpoint_ip.is_multicast:
   raise HTTPException(409,f"Node endpoint must be a public address, got {node.address}")
 except ValueError:
  if not node.address or any(ch.isspace() for ch in node.address) or node.address.lower() in {"localhost","localhost.localdomain"}:
   raise HTTPException(409,"Node endpoint hostname is invalid")

 # Download is idempotent: do not create another device/peer when the user
 # requests the same client's config again.
 existing_cred=db.query(ClientCredential).filter(
  ClientCredential.client_id==c.id,
  ClientCredential.revoked_at.is_(None)
 ).order_by(ClientCredential.created_at.desc()).first()
 if existing_cred:
  existing_artifact=db.query(ConfigArtifact).filter(
   ConfigArtifact.client_id==c.id,
   ConfigArtifact.tenant_id==admin.tenant_id,
   ConfigArtifact.protocol==inbound.protocol
  ).order_by(ConfigArtifact.expires_at.desc()).first()
  device=db.query(Device).filter(Device.id==existing_cred.device_id,Device.client_id==c.id).first()
  if inbound.protocol in {Protocol.wireguard,Protocol.amneziawg} and device and device.assigned_address:
   device.assigned_address=f"{ipaddress.ip_interface(device.assigned_address).ip}/32"
   wg=db.query(InboundWireGuard).filter(InboundWireGuard.inbound_id==inbound.id).first()
   material=json.loads(decrypt_secret(existing_cred.encrypted_private_material))
   if inbound.protocol in {Protocol.wireguard,Protocol.amneziawg}:
    derived_public=wg_public_key(decrypt_secret(wg.server_private_key_encrypted))
    if wg.server_public_key != derived_public: wg.server_public_key=derived_public
   awg_params=""
   if inbound.protocol==Protocol.amneziawg:
    awg_params=f"\nJc = 7\nJmin = 8\nJmax = 80\nS1 = {wg.amnezia_s1}\nS2 = {wg.amnezia_s2}\nS3 = {wg.amnezia_s3}\nS4 = {wg.amnezia_s4}\nH1 = {wg.amnezia_h1}\nH2 = {wg.amnezia_h2}\nH3 = {wg.amnezia_h3}\nH4 = {wg.amnezia_h4}"
   payload=f"[Interface]\nPrivateKey = {material['private_key']}\nAddress = {device.assigned_address}\nDNS = {inbound.dns or '1.1.1.1'}{awg_params}\n\n[Peer]\nPublicKey = {wg.server_public_key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {node.address}:{inbound.listen_port}\nPersistentKeepalive = 25\n"
   rendered=render_inbound(inbound,node,db)
   creds=db.query(ClientCredential,Device).join(Device,Device.id==ClientCredential.device_id).join(Client,Client.id==ClientCredential.client_id).filter(Client.inbound_id==inbound.id,Client.tenant_id==c.tenant_id,ClientCredential.revoked_at.is_(None)).all()
   peers=[]
   for cred_row,dev in creds:
    if not dev.assigned_address: continue
    peer_ip=f"{ipaddress.ip_interface(dev.assigned_address).ip}/32"
    peers += ["","[Peer]",f"PublicKey = {cred_row.public_identifier}",f"AllowedIPs = {peer_ip}"]
   apply_agent(node,rendered["protocol"],rendered["interface"],rendered["config"].rstrip()+"\n"+"\n".join(peers)+"\n",rendered.get("files"))
   refreshed=create_artifact(db,c,inbound.protocol,payload)
   return {"credential_id":existing_cred.id,"device_id":existing_cred.device_id,
           "artifact_id":refreshed.id,"public_identifier":existing_cred.public_identifier,
           "fingerprint":existing_cred.fingerprint,"expires_at":refreshed.expires_at}
  if existing_artifact:
   from ..services.config_artifacts import read_artifact
   try:
    read_artifact(existing_artifact)
    return {"credential_id":existing_cred.id,"device_id":existing_cred.device_id,
            "artifact_id":existing_artifact.id,"public_identifier":existing_cred.public_identifier,
            "fingerprint":existing_cred.fingerprint,"expires_at":existing_artifact.expires_at}
   except ValueError:
    payload=decrypt_secret(existing_artifact.encrypted_payload)
    refreshed=create_artifact(db,c,inbound.protocol,payload)
    return {"credential_id":existing_cred.id,"device_id":existing_cred.device_id,
            "artifact_id":refreshed.id,"public_identifier":existing_cred.public_identifier,
            "fingerprint":existing_cred.fingerprint,"expires_at":refreshed.expires_at}
 device=Device(tenant_id=c.tenant_id,client_id=c.id,fingerprint=fingerprint(c.id+str(__import__("time").time_ns())))
 if inbound.protocol in {Protocol.wireguard,Protocol.amneziawg}:
  server_ip=ipaddress.ip_interface(inbound.address).ip
  if ipaddress.ip_interface(c.assigned_address).ip==server_ip:
   network=ipaddress.ip_network(inbound.network,strict=False)
   used={ipaddress.ip_interface(x.assigned_address).ip for x in db.query(Client).filter(Client.inbound_id==inbound.id,Client.tenant_id==inbound.tenant_id).all() if x.id!=c.id}
   used.add(server_ip)
   for candidate in network.hosts():
    if candidate not in used:
     c.assigned_address=f"{candidate}/{ipaddress.ip_interface(c.assigned_address).network.prefixlen}"
     break
   else: raise HTTPException(409,"No free client address remains in this inbound")
  device.assigned_address=f"{ipaddress.ip_interface(allocate_device_address(db,c)).ip}/32"
  private,public=wg_keypair();identifier=public
  existing=db.query(InboundWireGuard).filter(InboundWireGuard.inbound_id==inbound.id).first()
  if not existing:raise HTTPException(409,"WireGuard inbound keys are not initialized")
  existing.server_public_key=wg_public_key(decrypt_secret(existing.server_private_key_encrypted))
  material={"private_key":private,"assigned_address":device.assigned_address}
  awg_params=""
  if inbound.protocol==Protocol.amneziawg:
   awg_params=f"\nJc = 7\nJmin = 8\nJmax = 80\nS1 = {existing.amnezia_s1}\nS2 = {existing.amnezia_s2}\nS3 = {existing.amnezia_s3}\nS4 = {existing.amnezia_s4}\nH1 = {existing.amnezia_h1}\nH2 = {existing.amnezia_h2}\nH3 = {existing.amnezia_h3}\nH4 = {existing.amnezia_h4}"
  payload=f"[Interface]\nPrivateKey = {private}\nAddress = {device.assigned_address}\nDNS = {inbound.dns or '1.1.1.1'}{awg_params}\n\n[Peer]\nPublicKey = {existing.server_public_key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {node.address}:{inbound.listen_port}\nPersistentKeepalive = 25\n"
 else:
  cert_key_source=db.query(InboundOpenVPN).filter(InboundOpenVPN.inbound_id==inbound.id).first()
  ov=cert_key_source
  if not ov:raise HTTPException(409,"OpenVPN inbound is not initialized")
  if not ov.ca_pem or not ov.ca_key_encrypted or not ov.tls_crypt_key_encrypted:
   ca,ca_key=openvpn_ca();server_cert,server_key=openvpn_server(ca,ca_key,"PRIMEVPN Server")
   ov.ca_pem=ca;ov.ca_key_encrypted=encrypt_secret(ca_key);ov.server_cert_pem=server_cert;ov.server_key_encrypted=encrypt_secret(server_key);ov.tls_crypt_key_encrypted=encrypt_secret(openvpn_tls_crypt_key());ov.crl_pem=create_empty_crl(ca,ca_key);db.flush()
  cert,key=openvpn_client(ov.ca_pem,decrypt_secret(ov.ca_key_encrypted),c.name)
  identifier=c.name;material={"certificate":cert,"private_key":key}
  payload=f"client\ndev tun\nproto {ov.transport}\nremote {node.address} {inbound.listen_port}\nremote-cert-tls server\ntls-version-min {ov.tls_min}\ndata-ciphers {ov.cipher_policy}\n<ca>\n{ov.ca_pem}</ca>\n<cert>\n{cert}</cert>\n<key>\n{key}</key>\n<tls-crypt>\n{decrypt_secret(ov.tls_crypt_key_encrypted)}\n</tls-crypt>\n"
 db.add(device)
 db.flush()
 fp=fingerprint(json.dumps(material,sort_keys=True))
 cred=ClientCredential(client_id=c.id,device_id=device.id,public_identifier=identifier,encrypted_private_material=encrypt_secret(json.dumps(material)),fingerprint=fp)
 db.add(cred);db.flush()
 if inbound.protocol in {Protocol.wireguard,Protocol.amneziawg}:
  rendered=render_inbound(inbound,node,db)
  creds=db.query(ClientCredential,Device).join(Device,Device.id==ClientCredential.device_id).join(Client,Client.id==ClientCredential.client_id).filter(Client.inbound_id==inbound.id,Client.tenant_id==c.tenant_id,ClientCredential.revoked_at.is_(None)).all()
  peers=[]
  for cred_row,dev in creds:
   if not dev.assigned_address: continue
   peer_ip=f"{ipaddress.ip_interface(dev.assigned_address).ip}/32"
   peers += ["","[Peer]",f"PublicKey = {cred_row.public_identifier}",f"AllowedIPs = {peer_ip}"]
  full_config=rendered["config"].rstrip()+"\n"+"\n".join(peers)+"\n"
  try:
   apply_agent(node,rendered["protocol"],rendered["interface"],full_config,rendered.get("files"))
  except Exception as e:
   db.rollback()
   raise HTTPException(502,f"WireGuard apply failed: {e}")
 artifact=create_artifact(db,c,inbound.protocol,payload)
 db.commit()
 return {"credential_id":cred.id,"device_id":device.id,"artifact_id":artifact.id,"public_identifier":identifier,"fingerprint":fp,"expires_at":artifact.expires_at}
