from fastapi import APIRouter,Depends,HTTPException,Request
from datetime import datetime,timezone
import ipaddress
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_tenant_manager
from ..models import Admin,Client,Inbound,InboundOpenVPN,ClientCredential,ResourceState,Protocol,Node
from ..schemas import ClientIn,ClientOut
from ..services.audit import record
from ..services.agent_client import revoke_wireguard_peer,deploy_openvpn_crl
from ..services.openvpn_revoke import revoke_certificate
from ..security import decrypt_secret
import json
router=APIRouter()

@router.get("",response_model=list[ClientOut])
def list_clients(admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 return db.query(Client).filter(Client.tenant_id==admin.tenant_id).order_by(Client.created_at.desc()).all()

@router.post("",response_model=ClientOut)
def create_client(data:ClientIn,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 inbound=db.query(Inbound).filter(Inbound.id==data.inbound_id,Inbound.tenant_id==admin.tenant_id).first()
 if not inbound:raise HTTPException(404,"Inbound not found")
 try:
  assigned=ipaddress.ip_interface(data.assigned_address)
  network=ipaddress.ip_network(inbound.network,strict=False)
  if assigned.ip not in network:raise HTTPException(422,"Assigned address is outside inbound network")
 except ValueError:raise HTTPException(422,"Invalid assigned address")
 if db.query(Client).filter(Client.inbound_id==inbound.id,Client.assigned_address==data.assigned_address,Client.tenant_id==admin.tenant_id).first():raise HTTPException(409,"Assigned address already in use")
 if db.query(Client).filter(Client.inbound_id==inbound.id,Client.name==data.name,Client.tenant_id==admin.tenant_id).first():raise HTTPException(409,"Client name already exists on this inbound")
 c=Client(tenant_id=admin.tenant_id,**data.model_dump());db.add(c);db.flush();record(db,admin,request,"client.create","client",c.id);db.commit();db.refresh(c);return c

@router.post("/{client_id}/revoke")
def revoke(client_id:str,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 c=db.query(Client).filter(Client.id==client_id,Client.tenant_id==admin.tenant_id).first()
 if not c:raise HTTPException(404,"Client not found")
 inbound=db.query(Inbound).filter(Inbound.id==c.inbound_id,Inbound.tenant_id==admin.tenant_id).first()
 node=db.query(Node).filter(Node.id==inbound.node_id,Node.tenant_id==admin.tenant_id).first() if inbound else None
 creds=db.query(ClientCredential).filter(ClientCredential.client_id==c.id,ClientCredential.revoked_at.is_(None)).order_by(ClientCredential.created_at.desc()).all()
 if inbound and node and node.agent_url and creds:
  try:
   if inbound.protocol in {Protocol.wireguard,Protocol.amneziawg}:
    for cred in creds: revoke_wireguard_peer(node,inbound.interface,cred.public_identifier)
   elif inbound.protocol==Protocol.openvpn:
    ov=db.query(InboundOpenVPN).filter(InboundOpenVPN.inbound_id==inbound.id).first()
    if ov and ov.ca_key_encrypted and ov.ca_pem:
     for cred in creds:
      if not cred.encrypted_private_material: continue
      material=json.loads(decrypt_secret(cred.encrypted_private_material))
      ov.crl_pem=revoke_certificate(ov.crl_pem,material["certificate"],decrypt_secret(ov.ca_key_encrypted),ov.ca_pem)
     deploy_openvpn_crl(node,inbound.interface,ov.crl_pem)
  except Exception as e:raise HTTPException(502,f"Node revocation failed: {e}")
 c.status=ResourceState.revoked
 for item in creds:item.revoked_at=datetime.now(timezone.utc)
 record(db,admin,request,"client.revoke","client",c.id);db.commit()
 return {"status":"revoked","client_id":c.id}
