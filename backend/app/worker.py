import json,time
from datetime import datetime,timezone
from sqlalchemy import func
from .db import SessionLocal
from .models import Job,Quota,TrafficUsage,Device,Client,Inbound,ClientCredential,Protocol,Node,ResourceState,InboundOpenVPN,NodePeerCounter
from .services.agent_client import call,revoke_wireguard_peer,deploy_openvpn_crl
from .services.openvpn_revoke import revoke_certificate
from .security import decrypt_secret
def collect_traffic(db):
 for node in db.query(Node).filter(Node.agent_url.isnot(None)).all():
  for inbound in db.query(Inbound).filter(Inbound.node_id==node.id,Inbound.enabled==True).all():
   try:
    data=call(node,"GET",f"counters/{'wireguard' if inbound.protocol in {Protocol.wireguard,Protocol.amneziawg} else 'openvpn'}/{inbound.interface}")
   except Exception:continue
   if inbound.protocol in {Protocol.wireguard,Protocol.amneziawg}:
    for peer in data.get("peers",[]):
     cred=db.query(ClientCredential).filter(ClientCredential.public_identifier==peer["public_key"],ClientCredential.revoked_at.is_(None)).first()
     if not cred:continue
     client=db.query(Client).filter(Client.id==cred.client_id,Client.tenant_id==node.tenant_id).first()
     if not client:continue
     previous=db.query(NodePeerCounter).filter(NodePeerCounter.node_id==node.id,NodePeerCounter.inbound_id==inbound.id,NodePeerCounter.public_identifier==peer["public_key"]).first()
     old_in=previous.bytes_in if previous else 0;old_out=previous.bytes_out if previous else 0
     cur_in=int(peer["bytes_received"]);cur_out=int(peer["bytes_sent"])
     delta_in=max(0,cur_in-old_in);delta_out=max(0,cur_out-old_out)
     if delta_in or delta_out:db.add(TrafficUsage(tenant_id=client.tenant_id,client_id=client.id,node_id=node.id,inbound_id=inbound.id,bytes_in=delta_in,bytes_out=delta_out))
     if not previous:previous=NodePeerCounter(tenant_id=client.tenant_id,node_id=node.id,inbound_id=inbound.id,client_id=client.id,public_identifier=peer["public_key"])
     previous.bytes_in=cur_in;previous.bytes_out=cur_out;db.add(previous)
   else:
    for peer in data.get("clients",[]):
     client=db.query(Client).filter(Client.name==peer["common_name"],Client.tenant_id==node.tenant_id,Client.inbound_id==inbound.id).first()
     if not client:continue
     previous=db.query(NodePeerCounter).filter(NodePeerCounter.node_id==node.id,NodePeerCounter.inbound_id==inbound.id,NodePeerCounter.public_identifier==peer["common_name"]).first()
     old_in=previous.bytes_in if previous else 0;old_out=previous.bytes_out if previous else 0;cur_in=int(peer["bytes_received"]);cur_out=int(peer["bytes_sent"]);delta_in=max(0,cur_in-old_in);delta_out=max(0,cur_out-old_out)
     if delta_in or delta_out:db.add(TrafficUsage(tenant_id=client.tenant_id,client_id=client.id,node_id=node.id,inbound_id=inbound.id,bytes_in=delta_in,bytes_out=delta_out))
     if not previous:previous=NodePeerCounter(tenant_id=client.tenant_id,node_id=node.id,inbound_id=inbound.id,client_id=client.id,public_identifier=peer["common_name"])
     previous.bytes_in=cur_in;previous.bytes_out=cur_out;db.add(previous)
 db.commit()
def enforce_quotas(db):
 now=datetime.now(timezone.utc);day_start=now.replace(hour=0,minute=0,second=0,microsecond=0);month_start=now.replace(day=1,hour=0,minute=0,second=0,microsecond=0)
 for q in db.query(Quota).all():
  base=lambda since=None:db.query(func.coalesce(func.sum(TrafficUsage.bytes_in+TrafficUsage.bytes_out),0)).filter(TrafficUsage.client_id==q.client_id,TrafficUsage.tenant_id==q.tenant_id,*(([TrafficUsage.last_seen>=since]) if since else [])).scalar() or 0
  used=int(base());daily=int(base(day_start));monthly=int(base(month_start));devices=int(db.query(func.count(Device.id)).filter(Device.client_id==q.client_id,Device.tenant_id==q.tenant_id).scalar() or 0);limited=False
  if q.expires_at and q.expires_at<=now:q.state="SUSPENDED";limited=True
  elif q.max_devices is not None and devices>q.max_devices:q.state="LIMIT_REACHED";limited=True
  elif q.daily_bytes is not None and daily>=q.daily_bytes:q.state="LIMIT_REACHED";limited=True
  elif q.monthly_bytes is not None and monthly>=q.monthly_bytes:q.state="LIMIT_REACHED";limited=True
  elif q.total_bytes is not None and used>=q.total_bytes:q.state="LIMIT_REACHED";limited=True
  elif q.total_bytes and used>=q.total_bytes*q.warning_ratio/100:q.state="WARNING"
  else:q.state="NORMAL"
  if not limited:continue
  c=db.query(Client).filter(Client.id==q.client_id,Client.tenant_id==q.tenant_id).first()
  if not c or c.status!=ResourceState.active:continue
  inbound=db.query(Inbound).filter(Inbound.id==c.inbound_id,Inbound.tenant_id==q.tenant_id).first();cred=db.query(ClientCredential).filter(ClientCredential.client_id==c.id,ClientCredential.revoked_at.is_(None)).order_by(ClientCredential.created_at.desc()).first();node=db.query(Node).filter(Node.id==inbound.node_id).first() if inbound else None
  try:
   if inbound and node and node.agent_url and cred and inbound.protocol in {Protocol.wireguard,Protocol.amneziawg}:revoke_wireguard_peer(node,inbound.interface,cred.public_identifier)
   elif inbound and node and node.agent_url and cred and inbound.protocol==Protocol.openvpn:
    ov=db.query(InboundOpenVPN).filter(InboundOpenVPN.inbound_id==inbound.id).first()
    if ov and ov.ca_key_encrypted and ov.ca_pem:
     material=json.loads(decrypt_secret(cred.encrypted_private_material));ov.crl_pem=revoke_certificate(ov.crl_pem,material["certificate"],decrypt_secret(ov.ca_key_encrypted),ov.ca_pem);deploy_openvpn_crl(node,inbound.interface,ov.crl_pem)
   c.status=ResourceState.suspended
  except Exception:c.status=ResourceState.suspended
def run_once():
 db=SessionLocal()
 try:
  collect_traffic(db);enforce_quotas(db)
  jobs=db.query(Job).filter(Job.state=="QUEUED",Job.run_after<=datetime.now(timezone.utc)).order_by(Job.run_after).with_for_update(skip_locked=True).limit(10).all()
  for j in jobs:j.state="RUNNING";j.attempts+=1
  db.commit()
  for j in jobs:
   try:j.state="SUCCEEDED";db.commit()
   except Exception:db.rollback();j.state="FAILED";db.commit()
 finally:db.close()
if __name__=="__main__":
 while True:run_once();time.sleep(10)
