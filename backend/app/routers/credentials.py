import json,ipaddress
from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_tenant_manager
from ..models import Admin,Client,Device,Inbound,InboundOpenVPN,InboundWireGuard,ClientCredential,Protocol,Node
from ..security import encrypt_secret,decrypt_secret
from ..services.credentials import wg_keypair,openvpn_ca,openvpn_server,openvpn_client,openvpn_tls_crypt_key,fingerprint
from ..services.config_artifacts import create_artifact
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
 inbound=db.query(Inbound).filter(Inbound.id==c.inbound_id,Inbound.tenant_id==admin.tenant_id).first()
 if not inbound:raise HTTPException(404,"Inbound not found")
 node=db.query(Node).filter(Node.id==inbound.node_id,Node.tenant_id==admin.tenant_id).first()
 if not node:raise HTTPException(404,"Node not found")
 device=Device(tenant_id=c.tenant_id,client_id=c.id,fingerprint=fingerprint(c.id+str(__import__("time").time_ns())))
 if inbound.protocol in {Protocol.wireguard,Protocol.amneziawg}:
  device.assigned_address=allocate_device_address(db,c)
  private,public=wg_keypair();identifier=public
  existing=db.query(InboundWireGuard).filter(InboundWireGuard.inbound_id==inbound.id).first()
  if not existing:raise HTTPException(409,"WireGuard inbound keys are not initialized")
  material={"private_key":private,"assigned_address":device.assigned_address}
  awg_params=""
  if inbound.protocol==Protocol.amneziawg:
   awg_params=f"\nJc = 7\nJmin = 8\nJmax = 80\nS1 = {existing.amnezia_s1}\nS2 = {existing.amnezia_s2}\nS3 = {existing.amnezia_s3}\nS4 = {existing.amnezia_s4}\nH1 = {existing.amnezia_h1}\nH2 = {existing.amnezia_h2}\nH3 = {existing.amnezia_h3}\nH4 = {existing.amnezia_h4}"
  payload=f"[Interface]\nPrivateKey = {private}\nAddress = {device.assigned_address}\nDNS = {inbound.dns or '1.1.1.1'}{awg_params}\n\n[Peer]\nPublicKey = {existing.server_public_key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {node.address}:{inbound.listen_port}\n"
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
 db.add(cred);db.flush();artifact=create_artifact(db,c,inbound.protocol,payload);db.commit()
 return {"credential_id":cred.id,"device_id":device.id,"artifact_id":artifact.id,"public_identifier":identifier,"fingerprint":fp,"expires_at":artifact.expires_at}
