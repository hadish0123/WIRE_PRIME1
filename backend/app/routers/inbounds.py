from fastapi import APIRouter,Depends,HTTPException,Request
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_tenant_manager
from ..models import Admin,Inbound,Node,InboundWireGuard,InboundOpenVPN,Protocol
from ..schemas import InboundIn,InboundOut
from ..services.audit import record
from ..services.credentials import wg_keypair,openvpn_ca,openvpn_server,openvpn_tls_crypt_key
from ..security import encrypt_secret
router=APIRouter()

@router.get("",response_model=list[InboundOut])
def list_inbounds(admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 return db.query(Inbound).filter(Inbound.tenant_id==admin.tenant_id).order_by(Inbound.created_at.desc()).all()

@router.post("",response_model=InboundOut)
def create_inbound(data:InboundIn,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 node=db.query(Node).filter(Node.id==data.node_id,Node.tenant_id==admin.tenant_id).first()
 if not node:raise HTTPException(404,"Node not found")
 item=Inbound(tenant_id=admin.tenant_id,**data.model_dump());db.add(item);db.flush()
 if data.protocol in {Protocol.wireguard,Protocol.amneziawg}:
  private,public=wg_keypair()
  db.add(InboundWireGuard(inbound_id=item.id,server_public_key=public,server_private_key_encrypted=encrypt_secret(private),amnezia_junk=7 if data.protocol==Protocol.amneziawg else None,amnezia_init=8 if data.protocol==Protocol.amneziawg else None,amnezia_response=80 if data.protocol==Protocol.amneziawg else None,amnezia_cookie=0 if data.protocol==Protocol.amneziawg else None))
 else:
  ca,ca_key=openvpn_ca();server_cert,server_key=openvpn_server(ca,ca_key,"PRIMEVPN Server")
  db.add(InboundOpenVPN(inbound_id=item.id,transport="udp",server_network=data.network,tls_min="1.2",tls_crypt=True,cipher_policy="AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",ca_pem=ca,server_cert_pem=server_cert,server_key_encrypted=encrypt_secret(server_key),ca_key_encrypted=encrypt_secret(ca_key),tls_crypt_key_encrypted=encrypt_secret(openvpn_tls_crypt_key())))
 record(db,admin,request,"inbound.create","inbound",item.id);db.commit();db.refresh(item);return item

@router.patch("/{inbound_id}",response_model=InboundOut)
def update_inbound(inbound_id:str,data:InboundIn,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 item=db.query(Inbound).filter(Inbound.id==inbound_id,Inbound.tenant_id==admin.tenant_id).first()
 if not item:raise HTTPException(404,"Inbound not found")
 node=db.query(Node).filter(Node.id==data.node_id,Node.tenant_id==admin.tenant_id).first()
 if not node:raise HTTPException(404,"Node not found")
 if item.protocol!=data.protocol:raise HTTPException(409,"Protocol changes require a new inbound")
 for k,v in data.model_dump().items():setattr(item,k,v)
 record(db,admin,request,"inbound.update","inbound",item.id);db.commit();db.refresh(item);return item
