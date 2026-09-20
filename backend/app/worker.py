import time
from datetime import datetime,timezone
from sqlalchemy import func
from .db import SessionLocal
from .models import Job,Quota,TrafficUsage,Device,Client,Inbound,ClientCredential,Protocol
from .services.agent_client import revoke_wireguard_peer
def enforce_quotas(db):
 now=datetime.now(timezone.utc);day_start=now.replace(hour=0,minute=0,second=0,microsecond=0);month_start=now.replace(day=1,hour=0,minute=0,second=0,microsecond=0)
 for q in db.query(Quota).all():
  base=lambda since=None:db.query(func.coalesce(func.sum(TrafficUsage.bytes_in+TrafficUsage.bytes_out),0)).filter(TrafficUsage.client_id==q.client_id,TrafficUsage.tenant_id==q.tenant_id,*(([TrafficUsage.last_seen>=since]) if since else [])).scalar() or 0
  used=int(base());daily=int(base(day_start));monthly=int(base(month_start));devices=int(db.query(func.count(Device.id)).filter(Device.client_id==q.client_id,Device.tenant_id==q.tenant_id).scalar() or 0)
  limited=False
  if q.expires_at and q.expires_at<=now:q.state="SUSPENDED";limited=True
  elif q.max_devices is not None and devices>q.max_devices:q.state="LIMIT_REACHED";limited=True
  elif q.daily_bytes is not None and daily>=q.daily_bytes:q.state="LIMIT_REACHED";limited=True
  elif q.monthly_bytes is not None and monthly>=q.monthly_bytes:q.state="LIMIT_REACHED";limited=True
  elif q.total_bytes is not None and used>=q.total_bytes:q.state="LIMIT_REACHED";limited=True
  elif q.total_bytes and used>=q.total_bytes*q.warning_ratio/100:q.state="WARNING"
  else:q.state="NORMAL"
  if limited:
   c=db.query(Client).filter(Client.id==q.client_id,Client.tenant_id==q.tenant_id).first()
   if c and c.status.value=="active":
    inbound=db.query(Inbound).filter(Inbound.id==c.inbound_id,Inbound.tenant_id==q.tenant_id).first()
    cred=db.query(ClientCredential).filter(ClientCredential.client_id=c.id,ClientCredential.revoked_at.is_(None)).order_by(ClientCredential.created_at.desc()).first()
    if inbound and inbound.protocol in {Protocol.wireguard,Protocol.amneziawg} and cred:
     node=db.query(__import__("app.models",fromlist=["Node"]).Node).filter(__import__("app.models",fromlist=["Node"]).Node.id==inbound.node_id).first()
     if node and node.agent_url:
      try:revoke_wireguard_peer(node,inbound.interface,cred.public_identifier)
      except Exception:pass
     c.status=__import__("app.models",fromlist=["ResourceState"]).ResourceState.suspended
def run_once():
 db=SessionLocal()
 try:
  enforce_quotas(db)
  jobs=db.query(Job).filter(Job.state=="QUEUED",Job.run_after<=datetime.now(timezone.utc)).order_by(Job.run_after).with_for_update(skip_locked=True).limit(10).all()
  for j in jobs:j.state="RUNNING";j.attempts+=1
  db.commit()
  for j in jobs:
   try:j.state="SUCCEEDED";db.commit()
   except Exception:db.rollback();j.state="FAILED";db.commit()
 finally:db.close()
if __name__=="__main__":
 while True:run_once();time.sleep(2)
