import time
from datetime import datetime,timezone
from sqlalchemy import func
from .db import SessionLocal
from .models import Job,Quota,TrafficUsage,Device
def enforce_quotas(db):
 now=datetime.now(timezone.utc);day_start=now.replace(hour=0,minute=0,second=0,microsecond=0);month_start=now.replace(day=1,hour=0,minute=0,second=0,microsecond=0)
 for q in db.query(Quota).all():
  base=lambda since=None:db.query(func.coalesce(func.sum(TrafficUsage.bytes_in+TrafficUsage.bytes_out),0)).filter(TrafficUsage.client_id==q.client_id,TrafficUsage.tenant_id==q.tenant_id,*(([TrafficUsage.last_seen>=since]) if since else [])).scalar() or 0
  used=int(base());daily=int(base(day_start));monthly=int(base(month_start))
  devices=int(db.query(func.count(Device.id)).filter(Device.client_id==q.client_id,Device.tenant_id==q.tenant_id).scalar() or 0)
  if q.expires_at and q.expires_at<=now:q.state="SUSPENDED"
  elif q.max_devices is not None and devices>q.max_devices:q.state="LIMIT_REACHED"
  elif q.daily_bytes is not None and daily>=q.daily_bytes:q.state="LIMIT_REACHED"
  elif q.monthly_bytes is not None and monthly>=q.monthly_bytes:q.state="LIMIT_REACHED"
  elif q.total_bytes is not None and used>=q.total_bytes:q.state="LIMIT_REACHED"
  elif q.total_bytes and used>=q.total_bytes*q.warning_ratio/100:q.state="WARNING"
  else:q.state="NORMAL"
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
