from datetime import datetime,timezone,timedelta
from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_tenant_manager,require_permission
from ..models import Admin,Client,Quota,TrafficUsage,TrafficSnapshot

router=APIRouter()

def _used_since(db,tenant_id,client_id,since):
    rows=db.query(TrafficSnapshot).filter(TrafficSnapshot.tenant_id==tenant_id,TrafficSnapshot.client_id==client_id,TrafficSnapshot.captured_at>=since).order_by(TrafficSnapshot.captured_at).all()
    if not rows:return 0
    prev=None;total=0
    for r in rows:
        cur=(int(r.bytes_in),int(r.bytes_out))
        if prev:total+=max(0,cur[0]-prev[0])+max(0,cur[1]-prev[1])
        prev=cur
    return total

def _usage(db,q,now):
    total=int(db.query(func.coalesce(func.sum(TrafficUsage.bytes_in+TrafficUsage.bytes_out),0)).filter(TrafficUsage.client_id==q.client_id,TrafficUsage.tenant_id==q.tenant_id).scalar() or 0)
    day=_used_since(db,q.tenant_id,q.client_id,now.replace(hour=0,minute=0,second=0,microsecond=0))
    month=_used_since(db,q.tenant_id,q.client_id,now.replace(day=1,hour=0,minute=0,second=0,microsecond=0))
    return total,day,month

def _state(q,total,daily,monthly,now):
    if q.expires_at and q.expires_at<=now:return "LIMIT_REACHED"
    limits=[(q.total_bytes,total),(q.daily_bytes,daily),(q.monthly_bytes,monthly)]
    if any(limit is not None and used>=limit for limit,used in limits):return "LIMIT_REACHED"
    if any(limit and used>=limit*q.warning_ratio/100 for limit,used in limits):return "WARNING"
    return "NORMAL"

@router.get("/overview/all")
def quota_overview(admin:Admin=Depends(require_permission("quota:read")),db:Session=Depends(get_db)):
    now=datetime.now(timezone.utc);items=[]
    for q in db.query(Quota).filter(Quota.tenant_id==admin.tenant_id).all():
        c=db.query(Client).filter(Client.id==q.client_id,Client.tenant_id==admin.tenant_id).first()
        if not c:continue
        total,daily,monthly=_usage(db,q,now);state=_state(q,total,daily,monthly,now);q.state=state
        def pct(used,limit):return None if not limit else min(100,round(used/limit*100,1))
        items.append({"client_id":c.id,"client_name":c.name,"state":state,"used_bytes":total,"daily_used_bytes":daily,"monthly_used_bytes":monthly,"total_bytes":q.total_bytes,"daily_bytes":q.daily_bytes,"monthly_bytes":q.monthly_bytes,"total_pct":pct(total,q.total_bytes),"daily_pct":pct(daily,q.daily_bytes),"monthly_pct":pct(monthly,q.monthly_bytes),"warning_ratio":q.warning_ratio,"max_devices":q.max_devices,"expires_at":q.expires_at})
    db.commit();items.sort(key=lambda x:(x["state"]!="LIMIT_REACHED",x["state"]!="WARNING",x["client_name"].lower()))
    return items

@router.get("/{client_id}")
def get_quota(client_id:str,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
    q=db.query(Quota).filter(Quota.client_id==client_id,Quota.tenant_id==admin.tenant_id).first()
    if not q:raise HTTPException(404,"Quota not found")
    return q

@router.post("")
def set_quota(body:dict,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
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
    now=datetime.now(timezone.utc);total,daily,monthly=_usage(db,q,now);state=_state(q,total,daily,monthly,now);q.state=state;db.commit()
    return {"state":state,"used_bytes":total,"daily_used_bytes":daily,"monthly_used_bytes":monthly,"total_bytes":q.total_bytes,"daily_bytes":q.daily_bytes,"monthly_bytes":q.monthly_bytes,"warning_ratio":q.warning_ratio,"expires_at":q.expires_at,"max_devices":q.max_devices}

