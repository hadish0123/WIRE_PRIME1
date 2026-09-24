from fastapi import APIRouter,Depends,HTTPException,Request
import ipaddress,re
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

def _validate_network(data):
 try:
  network=ipaddress.ip_network(data.network,strict=False)
  address=ipaddress.ip_interface(data.address)
 except ValueError:
  raise HTTPException(422,"Invalid inbound address/network")
 if address.version!=network.version or address.ip not in network:
  raise HTTPException(422,"Inbound address must belong to the inbound network")
 if address.network!=network:
  raise HTTPException(422,"Inbound address prefix must match the inbound network")
 if data.protocol in {Protocol.wireguard,Protocol.amneziawg} and network.version!=4:
  raise HTTPException(422,"Current WireGuard dataplane supports IPv4 tunnel networks only")
 if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}",data.interface):
  raise HTTPException(422,"Invalid interface name")

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
 _validate_network(data)
 node=db.query(Node).filter(Node.id==data.node_id,Node.tenant_id==admin.tenant_id).first()
 if not node:raise HTTPException(404,"Node not found")
 if not node.agent_url:raise HTTPException(409,"Node Agent is not configured")
 if db.query(Inbound).filter(Inbound.node_id==data.node_id,Inbound.listen_port==data.listen_port).first():raise HTTPException(409,"Port is already used on this node")
 if db.query(Inbound).filter(Inbound.node_id==data.node_id,Inbound.interface==data.interface).first():raise HTTPException(409,"Interface is already used on this node")
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
 _validate_network(data)
 item=db.query(Inbound).filter(Inbound.id==inbound_id,Inbound.tenant_id==admin.tenant_id).with_for_update().first()
 if not item:raise HTTPException(404,"Inbound not found")
 if data.node_id!=item.node_id or data.interface!=item.interface:
  raise HTTPException(409,"Moving an inbound or renaming its interface requires a new inbound")
 if data.network!=item.network or data.address!=item.address:
  from ..models import Client
  if db.query(Client.id).filter(Client.inbound_id==item.id).first():
   raise HTTPException(409,"Remove existing clients before changing the inbound network")
 if item.protocol!=data.protocol:raise HTTPException(409,"Protocol changes require a new inbound")
 node=db.query(Node).filter(Node.id==data.node_id,Node.tenant_id==admin.tenant_id).first()
 if not node:raise HTTPException(404,"Node not found")
 if data.node_id!=item.node_id or data.listen_port!=item.listen_port:
  if db.query(Inbound).filter(Inbound.node_id==data.node_id,Inbound.listen_port==data.listen_port,Inbound.id!=item.id).first():raise HTTPException(409,"Port is already used on this node")
 if db.query(Inbound).filter(Inbound.node_id==data.node_id,Inbound.interface==data.interface,Inbound.id!=item.id).first():raise HTTPException(409,"Interface is already used on this node")
 for k,v in data.model_dump().items():setattr(item,k,v)
 db.flush()
 try:
  rendered=render_inbound(item,node,db);apply_agent(node,rendered["protocol"],rendered["interface"],rendered["config"],rendered["files"])
 except Exception as e:
  db.rollback();raise HTTPException(502,f"Inbound apply failed: {e}")
 record(db,admin,request,"inbound.update","inbound",item.id);db.commit();db.refresh(item);return item

@router.post("/{inbound_id}/sync",response_model=InboundOut)
def sync_inbound(inbound_id:str,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 item=db.query(Inbound).filter(Inbound.id==inbound_id,Inbound.tenant_id==admin.tenant_id).with_for_update().first()
 if not item:raise HTTPException(404,"Inbound not found")
 node=_node(db,item,admin.tenant_id)
 try:
  rendered=render_inbound(item,node,db);apply_agent(node,rendered["protocol"],rendered["interface"],rendered["config"],rendered["files"])
 except Exception as e:raise HTTPException(502,f"Inbound sync failed: {e}")
 record(db,admin,request,"inbound.sync","inbound",item.id);db.commit();db.refresh(item);return item

@router.delete("/{inbound_id}",status_code=204)
def delete_inbound(inbound_id:str,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 item=db.query(Inbound).filter(Inbound.id==inbound_id,Inbound.tenant_id==admin.tenant_id).with_for_update().first()
 if not item:raise HTTPException(404,"Inbound not found")
 node=db.query(Node).filter(Node.id==item.node_id,Node.tenant_id==admin.tenant_id).first()
 if not node:raise HTTPException(404,"Node not found")
 try:
  # Deletion must remain possible while a node is AUTHENTICATING/OFFLINE.
  # If the agent is reachable, remove the runtime interface before deleting DB state.
  if node.agent_url:
   remove_agent(node,item.protocol.value,item.interface)
 except Exception as e:
  # The DB resource must still be deletable when the old Node Agent is offline.
  # The runtime interface will disappear when that node is reinstalled/removed.
  if "connection failed" not in str(e).lower() and "connection refused" not in str(e).lower():
   raise HTTPException(502,f"Inbound runtime remove failed: {e}")
 record(db,admin,request,"inbound.delete","inbound",item.id)
 db.delete(item)
 db.commit()
