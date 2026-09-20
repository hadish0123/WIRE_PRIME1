from datetime import datetime,timezone
from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_tenant_manager
from ..models import Admin,Client,Quota,TrafficUsage
router=APIRouter()
@router.get("/{client_id}")
def get_quota(client_id:str,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 q=db.query(Quota).filter(Quota.client_id==client_id,Quota.tenant_id==admin.tenant_id).first()
 if not q:raise HTTPException(404,"Quota not found")
 return q
@router.post("")
def set_quota(body:dict,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 cid=body.get("client_id");c=db.query(Client).filter(Client.id==cid,Client.tenant_id==admin.tenant_id).first()
 if not c:raise HTTPException(404,"Client not found")
 q=db.query(Quota).filter(Quota.client_id==cid,Quota.tenant_id==admin.tenant_id).first()
 if not q:q=Quota(client_id=cid,tenant_id=admin.tenant_id);db.add(q)
 for k in ("total_bytes","daily_bytes","monthly_bytes","max_devices","warning_ratio","expires_at"):
  if k in body:setattr(q,k,body[k])
 if q.warning_ratio<1 or q.warning_ratio>100:raise HTTPException(422,"warning_ratio must be 1..100")
 db.commit();db.refresh(q);return q
@router.get("/{client_id}/state")
def quota_state(client_id:str,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 q=db.query(Quota).filter(Quota.client_id==client_id,Quota.tenant_id==admin.tenant_id).first()
 if not q:raise HTTPException(404,"Quota not found")
 used=int(db.query(func.coalesce(func.sum(TrafficUsage.bytes_in+TrafficUsage.bytes_out),0)).filter(TrafficUsage.client_id==client_id,TrafficUsage.tenant_id==admin.tenant_id).scalar() or 0)
 now=datetime.now(timezone.utc);state="NORMAL"
 if q.expires_at and q.expires_at<=now:state="LIMIT_REACHED"
 elif q.total_bytes is not None and used>=q.total_bytes:state="LIMIT_REACHED"
 elif q.total_bytes and used>=q.total_bytes*q.warning_ratio/100:state="WARNING"
 q.state=state;db.commit()
 return {"state":state,"used_bytes":used,"total_bytes":q.total_bytes}