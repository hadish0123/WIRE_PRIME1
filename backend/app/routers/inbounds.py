from fastapi import APIRouter,Depends,HTTPException,Request
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_tenant_manager,require_permission
from ..models import Admin,Inbound,Node,InboundWireGuard,InboundOpenVPN,Protocol
from ..schemas import InboundIn,InboundOut
from ..services.audit import record
from ..services.credentials import wg_keypair,openvpn_ca,openvpn_server,openvpn_tls_crypt_key
from ..security import encrypt_secret
from ..services.openvpn_revoke import create_empty_crl
from ..services.inbound_config import render_inbound
from ..services.agent_client import apply as apply_agent,remove as remove_agent
router=APIRouter()

def _node(db,inbound,tenant_id):
 node=db.query(Node).filter(Node.id==inbound.node_id,Node.tenant_id==tenant_id).first()
 if not node:raise HTTPException(404,"Node not found")
 if not node.agent_url or str(node.state).split(".")[-1].lower() not in {"ready","degraded"}:
  raise HTTPException(409,"Node Agent is not ready")
 return node

@router.get("",response_model=list[InboundOut])
def list_inbounds(admin:Admin=Depends(require_permission("inbounds:read")),db:Session=Depends(get_db)):
 return db.query(Inbound).filter(Inbound.tenant_id==admin.tenant_id).order_by(Inbound.created_at.desc()).all()

@router.post("",response_model=InboundOut)
def create_inbound(data:InboundIn,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 node=db.query(Node).filter(Node.id==data.node_id,Node.tenant_id==admin.tenant_id).first()
 if not node:raise HTTPException(404,"Node not found")
 if not node.agent_url:raise HTTPException(409,"Node Agent is not configured")
 if db.query(Inbound).filter(Inbound.node_id==data.node_id,Inbound.listen_port==data.listen_port).first():raise HTTPException(409,"Port is already used on this node")
 item=Inbound(tenant_id=admin.tenant_id,**data.model_dump());db.add(item);db.flush()
 if data.protocol in {Protocol.wireguard,Protocol.amneziawg}:
  private,public=wg_keypair()
  db.add(InboundWireGuard(inbound_id=item.id,server_public_key=public,server_private_key_encrypted=encrypt_secret(private),amnezia_junk=7 if data.protocol==Protocol.amneziawg else None,amnezia_init=8 if data.protocol==Protocol.amneziawg else None,amnezia_response=80 if data.protocol==Protocol.amneziawg else None,amnezia_cookie=0 if data.protocol==Protocol.amneziawg else None))
 else:
  ca,ca_key=openvpn_ca();server_cert,server_key=openvpn_server(ca,ca_key,"PRIMEVPN Server")
  db.add(InboundOpenVPN(inbound_id=item.id,transport="udp",server_network=data.network,tls_min="1.2",tls_crypt=True,cipher_policy="AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",ca_pem=ca,server_cert_pem=server_cert,server_key_encrypted=encrypt_secret(server_key),ca_key_encrypted=encrypt_secret(ca_key),tls_crypt_key_encrypted=encrypt_secret(openvpn_tls_crypt_key()),crl_pem=create_empty_crl(ca,ca_key)))
 db.flush()
 try:
  rendered=render_inbound(item,node,db);apply_agent(node,rendered["protocol"],rendered["interface"],rendered["config"],rendered["files"])
 except Exception as e:
  db.rollback();raise HTTPException(502,f"Inbound apply failed: {e}")
 record(db,admin,request,"inbound.create","inbound",item.id);db.commit();db.refresh(item);return item

@router.patch("/{inbound_id}",response_model=InboundOut)
def update_inbound(inbound_id:str,data:InboundIn,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 item=db.query(Inbound).filter(Inbound.id==inbound_id,Inbound.tenant_id==admin.tenant_id).first()
 if not item:raise HTTPException(404,"Inbound not found")
 if item.protocol!=data.protocol:raise HTTPException(409,"Protocol changes require a new inbound")
 node=db.query(Node).filter(Node.id==data.node_id,Node.tenant_id==admin.tenant_id).first()
 if not node:raise HTTPException(404,"Node not found")
 if data.node_id!=item.node_id or data.listen_port!=item.listen_port:
  if db.query(Inbound).filter(Inbound.node_id==data.node_id,Inbound.listen_port==data.listen_port,Inbound.id!=item.id).first():raise HTTPException(409,"Port is already used on this node")
 for k,v in data.model_dump().items():setattr(item,k,v)
 db.flush()
 try:
  rendered=render_inbound(item,node,db);apply_agent(node,rendered["protocol"],rendered["interface"],rendered["config"],rendered["files"])
 except Exception as e:
  db.rollback();raise HTTPException(502,f"Inbound apply failed: {e}")
 record(db,admin,request,"inbound.update","inbound",item.id);db.commit();db.refresh(item);return item

@router.post("/{inbound_id}/sync",response_model=InboundOut)
def sync_inbound(inbound_id:str,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 item=db.query(Inbound).filter(Inbound.id==inbound_id,Inbound.tenant_id==admin.tenant_id).first()
 if not item:raise HTTPException(404,"Inbound not found")
 node=_node(db,item,admin.tenant_id)
 try:
  rendered=render_inbound(item,node,db);apply_agent(node,rendered["protocol"],rendered["interface"],rendered["config"],rendered["files"])
 except Exception as e:raise HTTPException(502,f"Inbound sync failed: {e}")
 record(db,admin,request,"inbound.sync","inbound",item.id);db.commit();db.refresh(item);return item

@router.delete("/{inbound_id}",status_code=204)
def delete_inbound(inbound_id:str,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 item=db.query(Inbound).filter(Inbound.id==inbound_id,Inbound.tenant_id==admin.tenant_id).first()
 if not item:raise HTTPException(404,"Inbound not found")
 node=_node(db,item,admin.tenant_id)
 if db.query(__import__("app.models",fromlist=["Client"]).Client).filter_by(inbound_id=item.id).count():raise HTTPException(409,"Inbound has clients; revoke/remove clients first")
 try:remove_agent(node,item.protocol.value,item.interface)
 except Exception as e:raise HTTPException(502,f"Inbound remove failed: {e}")
 record(db,admin,request,"inbound.delete","inbound",item.id);db.delete(item);db.commit()
