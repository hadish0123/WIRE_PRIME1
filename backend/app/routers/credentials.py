import json
from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin
from ..models import Admin,Client,Inbound,InboundOpenVPN,InboundWireGuard,ClientCredential,Protocol
from ..security import encrypt_secret
from ..services.credentials import wg_keypair,openvpn_ca,openvpn_client,fingerprint
from ..services.config_artifacts import create_artifact
router=APIRouter()
@router.post("/{client_id}/credentials")
def issue(client_id:str,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 c=db.query(Client).filter(Client.id==client_id,Client.tenant_id==admin.tenant_id).first()
 if not c:raise HTTPException(404,"Client not found")
 inbound=db.query(Inbound).filter(Inbound.id==c.inbound_id,Inbound.tenant_id==admin.tenant_id).first()
 if not inbound:raise HTTPException(404,"Inbound not found")
 if inbound.protocol in {Protocol.wireguard,Protocol.amneziawg}:
  private,public=wg_keypair();material={"private_key":private}
  identifier=public
  existing=db.query(InboundWireGuard).filter(InboundWireGuard.inbound_id==inbound.id).first()
  if not existing:raise HTTPException(409,"WireGuard inbound keys are not initialized")
  payload=f"[Interface]\nPrivateKey = {private}\nAddress = {c.assigned_address}\nDNS = {inbound.dns or '1.1.1.1'}\n\n[Peer]\nPublicKey = {existing.server_public_key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {inbound.address}:{inbound.listen_port}\n"
 else:
  ov=db.query(InboundOpenVPN).filter(InboundOpenVPN.inbound_id==inbound.id).first()
  if not ov:raise HTTPException(409,"OpenVPN inbound is not initialized")
  if not ov.ca_pem or not ov.server_key_encrypted:
   ca,ca_key=openvpn_ca();ov.ca_pem=ca;ov.server_key_encrypted=encrypt_secret(ca_key);db.commit()
  cert,key=openvpn_client(ov.ca_pem,__import__("app.security",fromlist=["decrypt_secret"]).decrypt_secret(ov.server_key_encrypted),c.name)
  identifier=c.name;material={"certificate":cert,"private_key":key}
  payload=f"client\ndev tun\nproto {ov.transport}\nremote {inbound.address} {inbound.listen_port}\nremote-cert-tls server\ntls-version-min {ov.tls_min}\ndata-ciphers {ov.cipher_policy}\n<ca>\n{ov.ca_pem}</ca>\n<cert>\n{cert}</cert>\n<key>\n{key}</key>\n"
 fp=fingerprint(json.dumps(material,sort_keys=True))
 cred=ClientCredential(client_id=c.id,public_identifier=identifier,encrypted_private_material=encrypt_secret(json.dumps(material)),fingerprint=fp)
 db.add(cred);db.flush();artifact=create_artifact(db,c,inbound.protocol,payload)
 db.commit()
 return {"credential_id":cred.id,"artifact_id":artifact.id,"public_identifier":identifier,"fingerprint":fp,"expires_at":artifact.expires_at}
