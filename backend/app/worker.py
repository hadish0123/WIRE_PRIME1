import time
from datetime import datetime,timezone,timedelta
from sqlalchemy import func,select
from .db import SessionLocal
from .models import Job,Quota,TrafficUsage
def enforce_quotas(db):
 now=datetime.now(timezone.utc)
 quotas=db.query(Quota).all()
 for q in quotas:
  used=int(db.query(func.coalesce(func.sum(TrafficUsage.bytes_in+TrafficUsage.bytes_out),0)).filter(TrafficUsage.client_id==q.client_id,TrafficUsage.tenant_id==q.tenant_id).scalar() or 0)
  state="NORMAL"
  if q.expires_at and q.expires_at<=now:state="SUSPENDED"
  elif q.total_bytes is not None and used>=q.total_bytes:state="LIMIT_REACHED"
  elif q.total_bytes and used>=q.total_bytes*q.warning_ratio/100:state="WARNING"
  q.state=state
def run_once():
 db=SessionLocal()
 try:
  enforce_quotas(db)
  jobs=db.query(Job).filter(Job.state=="QUEUED",Job.run_after<=datetime.now(timezone.utc)).order_by(Job.run_after).with_for_update(skip_locked=True).limit(10).all()
  for j in jobs:j.state="RUNNING";j.attempts+=1
  db.commit()
  for j in jobs:
   try:
    j.state="SUCCEEDED";db.commit()
   except Exception:
    db.rollback();j.state="FAILED";db.commit()
 finally:db.close()
if __name__=="__main__":
 while True:
  run_once();time.sleep(2)
