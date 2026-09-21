from datetime import datetime, timezone, timedelta
import ipaddress
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin, require_tenant_manager, can_access_client, representative_can_use_inbound, admin_quota_state
from ..models import Admin, Client, Device, Inbound, RoleName, InboundOpenVPN, ClientCredential, ResourceState, Protocol, Node, TrafficUsage, TrafficSnapshot, Session as ClientSession, Quota
from ..schemas import ClientIn, ClientOut, ClientDetailOut, ClientUpdateIn, DeviceOut
from ..services.audit import record
from ..services.agent_client import revoke_wireguard_peer, deploy_openvpn_crl
from ..services.openvpn_revoke import revoke_certificate
from ..security import decrypt_secret
import json

router=APIRouter()

def _normalize_expiry(value):
 if value is None:return None
 if value.tzinfo is None:return value.replace(tzinfo=timezone.utc)
 return value.astimezone(timezone.utc)

def _validate_address(inbound,address):
 try:
  assigned=ipaddress.ip_interface(address)
  network=ipaddress.ip_network(inbound.network,strict=False)
  if assigned.version!=network.version or assigned.ip not in network:raise HTTPException(422,"Assigned address is outside inbound network")
  if assigned.ip==network.network_address:raise HTTPException(422,"Network address cannot be assigned to a client")
  if assigned.ip==ipaddress.ip_interface(inbound.address).ip:raise HTTPException(422,"Inbound server address cannot be assigned to a client")
  if network.version==4 and assigned.ip==network.broadcast_address:raise HTTPException(422,"Broadcast address cannot be assigned to a client")
 except ValueError:raise HTTPException(422,"Invalid assigned address")

def _detail(db,c,now):
 inbound=db.query(Inbound).filter(Inbound.id==c.inbound_id,Inbound.tenant_id==c.tenant_id).first()
 node=db.query(Node).filter(Node.id==inbound.node_id,Node.tenant_id==c.tenant_id).first() if inbound else None
 bin_,bout=db.query(func.coalesce(func.sum(TrafficUsage.bytes_in),0),func.coalesce(func.sum(TrafficUsage.bytes_out),0)).filter(TrafficUsage.client_id==c.id,TrafficUsage.tenant_id==c.tenant_id).one()
 device_count=db.query(Device).filter(Device.client_id==c.id,Device.tenant_id==c.tenant_id).count()
 cutoff=now-timedelta(seconds=180)
 online=db.query(ClientSession.id).filter(ClientSession.client_id==c.id,ClientSession.tenant_id==c.tenant_id,ClientSession.ended_at.is_(None),ClientSession.last_seen_at>=cutoff).first() is not None
 last_seen=db.query(func.max(ClientSession.last_seen_at)).filter(ClientSession.client_id==c.id,ClientSession.tenant_id==c.tenant_id).scalar()
 q=db.query(Quota).filter(Quota.client_id==c.id,Quota.tenant_id==c.tenant_id).first()
 used=int(bin_ or 0)+int(bout or 0)
 qstate=None
 if q:
  qstate="NORMAL"
  qexp=_normalize_expiry(q.expires_at)
  snap=db.query(TrafficSnapshot).filter(TrafficSnapshot.client_id==c.id,TrafficSnapshot.tenant_id==c.tenant_id,TrafficSnapshot.captured_at>=now.replace(hour=0,minute=0,second=0,microsecond=0)).order_by(TrafficSnapshot.captured_at).all()
  daily_used=0;monthly_used=0
  if snap:
   prev=None
   for s in snap:
    cur=(int(s.bytes_in),int(s.bytes_out))
    if prev:daily_used+=max(0,cur[0]-prev[0])+max(0,cur[1]-prev[1])
    prev=cur
  msince=now.replace(day=1,hour=0,minute=0,second=0,microsecond=0)
  msnap=db.query(TrafficSnapshot).filter(TrafficSnapshot.client_id==c.id,TrafficSnapshot.tenant_id==c.tenant_id,TrafficSnapshot.captured_at>=msince).order_by(TrafficSnapshot.captured_at).all()
  prev=None
  for s in msnap:
   cur=(int(s.bytes_in),int(s.bytes_out))
   if prev:monthly_used+=max(0,cur[0]-prev[0])+max(0,cur[1]-prev[1])
   prev=cur
  if qexp and qexp<=now:qstate="LIMIT_REACHED"
  elif q.total_bytes is not None and used>=q.total_bytes:qstate="LIMIT_REACHED"
  elif q.daily_bytes is not None and daily_used>=q.daily_bytes:qstate="LIMIT_REACHED"
  elif q.monthly_bytes is not None and monthly_used>=q.monthly_bytes:qstate="LIMIT_REACHED"
  elif (q.total_bytes and used>=q.total_bytes*q.warning_ratio/100) or (q.daily_bytes and daily_used>=q.daily_bytes*q.warning_ratio/100) or (q.monthly_bytes and monthly_used>=q.monthly_bytes*q.warning_ratio/100):qstate="WARNING"
 status=c.status.value if hasattr(c.status,"value") else str(c.status)
 exp=_normalize_expiry(c.expires_at)
 if status=="ACTIVE" and exp and exp<=now:status="EXPIRED"
 return {"id":c.id,"inbound_id":c.inbound_id,"inbound_name":inbound.name if inbound else "—","protocol":inbound.protocol if inbound else Protocol.wireguard,"node_id":inbound.node_id if inbound else "","node_name":node.name if node else "—","listen_port":inbound.listen_port if inbound else 0,"name":c.name,"status":status,"assigned_address":c.assigned_address,"expires_at":exp,"created_at":c.created_at,"traffic_in":int(bin_ or 0),"traffic_out":int(bout or 0),"total_traffic":used,"quota_total":q.total_bytes if q else None,"quota_daily":q.daily_bytes if q else None,"quota_monthly":q.monthly_bytes if q else None,"quota_used":used,"quota_state":qstate,"quota_warning_ratio":q.warning_ratio if q else None,"quota_expires_at":_normalize_expiry(q.expires_at) if q else None,"max_devices":q.max_devices if q else None,"devices_count":device_count,"online":online,"last_seen_at":last_seen}

@router.get("",response_model=list[ClientDetailOut])
def list_clients(search:str|None=Query(default=None,max_length=100),status:str|None=Query(default=None,max_length=30),inbound_id:str|None=None,protocol:Protocol|None=None,online:bool|None=None,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 q=db.query(Client)
 if admin.role!=RoleName.platform_owner:q=q.filter(Client.tenant_id==admin.tenant_id)
 if admin.role==RoleName.representative:q=q.filter(Client.created_by_admin_id==admin.id)
 rows=q.order_by(Client.created_at.desc()).all()
 now=datetime.now(timezone.utc)
 result=[_detail(db,c,now) for c in rows]
 if search:
  q=search.strip().lower()
  result=[x for x in result if q in x["name"].lower() or q in x["assigned_address"].lower() or q in x["inbound_name"].lower() or q in x["node_name"].lower()]
 if status:result=[x for x in result if x["status"].lower()==status.lower()]
 if inbound_id:result=[x for x in result if x["inbound_id"]==inbound_id]
 if protocol:result=[x for x in result if x["protocol"]==protocol]
 if online is not None:result=[x for x in result if x["online"]==online]
 return result

@router.post("",response_model=ClientOut)
def create_client(data:ClientIn,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 quota_state,_,_=admin_quota_state(db,admin)
 if quota_state=="EXPIRED":raise HTTPException(403,"Admin access period expired")
 if quota_state=="LIMIT_REACHED":raise HTTPException(403,"Admin traffic quota reached")
 inbound_q=db.query(Inbound).filter(Inbound.id==data.inbound_id)
 if admin.role!=RoleName.platform_owner:inbound_q=inbound_q.filter(Inbound.tenant_id==admin.tenant_id)
 inbound=inbound_q.first()
 if not inbound:raise HTTPException(404,"Inbound not found")
 if not representative_can_use_inbound(db,admin,inbound.id):raise HTTPException(403,"Inbound is not assigned to this representative")
 expires=_normalize_expiry(data.expires_at)
 if expires and expires<=datetime.now(timezone.utc):raise HTTPException(422,"Client expiry must be in the future")
 _validate_address(inbound,data.assigned_address)
 assigned_address=data.assigned_address
 if db.query(Client).filter(Client.inbound_id==inbound.id,Client.assigned_address==assigned_address,Client.tenant_id==inbound.tenant_id).first():
  network=ipaddress.ip_network(inbound.network,strict=False)
  prefix=ipaddress.ip_interface(assigned_address).network.prefixlen
  used={ipaddress.ip_interface(v.assigned_address).ip for v in db.query(Client).filter(Client.inbound_id==inbound.id,Client.tenant_id==inbound.tenant_id).all()}
  used.add(ipaddress.ip_interface(inbound.address).ip)
  for candidate in network.hosts():
   if candidate not in used:
    assigned_address=f"{candidate}/{prefix}"
    break
  else: raise HTTPException(409,"No free client address remains in this inbound")
 if db.query(Client).filter(Client.inbound_id==inbound.id,Client.assigned_address==assigned_address,Client.tenant_id==inbound.tenant_id).first():raise HTTPException(409,"Assigned address already in use")
 if db.query(Client).filter(Client.inbound_id==inbound.id,Client.name==data.name,Client.tenant_id==inbound.tenant_id).first():raise HTTPException(409,"Client name already exists on this inbound")
 c=Client(tenant_id=inbound.tenant_id,inbound_id=data.inbound_id,created_by_admin_id=admin.id,name=data.name,assigned_address=assigned_address,expires_at=expires)
 db.add(c);db.flush()
 if any(v is not None for v in (data.total_bytes,data.daily_bytes,data.monthly_bytes,data.max_devices)) or expires:
  q=Quota(tenant_id=c.tenant_id,client_id=c.id,total_bytes=data.total_bytes,daily_bytes=data.daily_bytes,monthly_bytes=data.monthly_bytes,max_devices=data.max_devices,warning_ratio=data.warning_ratio,expires_at=expires)
  db.add(q)
 record(db,admin,request,"client.create","client",c.id);db.commit();db.refresh(c);return c

@router.delete("/{client_id}")
def delete_client(client_id:str,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
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
  except Exception as e:raise HTTPException(502,f"Node client removal failed: {e}")
 record(db,admin,request,"client.delete","client",c.id);db.delete(c);db.commit()
 return {"status":"deleted","client_id":client_id}

@router.patch("/{client_id}",response_model=ClientOut)
def update_client(client_id:str,data:ClientUpdateIn,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 c=db.query(Client).filter(Client.id==client_id).first()
 if not can_access_client(db,admin,c):raise HTTPException(404,"Client not found")
 if c.status==ResourceState.revoked:raise HTTPException(409,"Revoked client cannot be edited")
 expires=_normalize_expiry(data.expires_at) if data.expires_at is not None else c.expires_at
 if expires and expires<=datetime.now(timezone.utc):raise HTTPException(422,"Client expiry must be in the future")
 if data.name and db.query(Client).filter(Client.inbound_id==c.inbound_id,Client.name==data.name,Client.id!=c.id,Client.tenant_id==admin.tenant_id).first():raise HTTPException(409,"Client name already exists on this inbound")
 if data.name is not None:c.name=data.name
 if data.expires_at is not None:c.expires_at=expires
 q=db.query(Quota).filter(Quota.client_id==c.id,Quota.tenant_id==c.tenant_id).first()
 quota_fields=any(v is not None for v in (data.total_bytes,data.daily_bytes,data.monthly_bytes,data.max_devices,data.warning_ratio))
 if quota_fields or data.expires_at is not None:
  if not q:q=Quota(tenant_id=admin.tenant_id,client_id=c.id);db.add(q)
  if data.total_bytes is not None:q.total_bytes=data.total_bytes
  if data.daily_bytes is not None:q.daily_bytes=data.daily_bytes
  if data.monthly_bytes is not None:q.monthly_bytes=data.monthly_bytes
  if data.max_devices is not None:q.max_devices=data.max_devices
  if data.warning_ratio is not None:q.warning_ratio=data.warning_ratio
  if data.expires_at is not None:q.expires_at=expires
  if q.warning_ratio<1 or q.warning_ratio>100:raise HTTPException(422,"warning_ratio must be 1..100")
 record(db,admin,request,"client.update","client",c.id);db.commit();db.refresh(c);return c

@router.get("/{client_id}/devices",response_model=list[DeviceOut])
def list_devices(client_id:str,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 c=db.query(Client).filter(Client.id==client_id).first()
 if not can_access_client(db,admin,c):raise HTTPException(404,"Client not found")
 return db.query(Device).filter(Device.client_id==c.id,Device.tenant_id==admin.tenant_id).order_by(Device.last_seen_at.desc().nullslast()).all()

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
