import time
from .db import SessionLocal
from .models import Job
def run_once():
 db=SessionLocal()
 try:
  jobs=db.query(Job).filter(Job.state=="QUEUED").order_by(Job.run_after).limit(10).with_for_update(skip_locked=True).all()
  for j in jobs:j.state="RUNNING";j.attempts+=1
  db.commit()
 finally:db.close()
if __name__=="__main__":
 while True:run_once();time.sleep(2)