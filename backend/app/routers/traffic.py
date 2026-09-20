from datetime import datetime,timezone,timedelta
from collections import defaultdict
from fastapi import APIRouter,Depends,HTTPException,Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..db import get_db
from ..deps import current_admin,require_tenant_manager
from ..models import Admin,TrafficUsage,TrafficSnapshot,Client,Inbound,Node,Quota

router=APIRouter()

def _tenant_usage(db,tenant_id):
    a,b=db.query(func.coalesce(func.sum(TrafficUsage.bytes_in),0),func.coalesce(func.sum(TrafficUsage.bytes_out),0)).filter(TrafficUsage.tenant_id==tenant_id).one()
    return int(a),int(b)

def _snapshot_delta(db,tenant_id,client_id=None,since=None):
    q=db.query(TrafficSnapshot).filter(TrafficSnapshot.tenant_id==tenant_id)
    if client_id:q=q.filter(TrafficSnapshot.client_id==client_id)
    if since:q=q.filter(TrafficSnapshot.captured_at>=since)
    rows=q.order_by(TrafficSnapshot.client_id,TrafficSnapshot.captured_at).all()
    prev={}
    total=0
    for r in rows:
        key=r.client_id
        old=prev.get(key)
        cur=int(r.bytes_in)+int(r.bytes_out)
        if old is not None:
            total+=max(0,cur-old)
        prev[key]=cur
    return total

@router.post("/collect")
def collect(admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
    now=datetime.now(timezone.utc)
    rows=db.query(TrafficUsage).filter(TrafficUsage.tenant_id==admin.tenant_id).all()
    for r in rows:
        db.add(TrafficSnapshot(tenant_id=r.tenant_id,client_id=r.client_id,node_id=r.node_id,inbound_id=r.inbound_id,bytes_in=r.bytes_in,bytes_out=r.bytes_out,captured_at=now))
    db.commit()
    return {"captured_at":now,"rows":len(rows)}

@router.get("/summary")
def summary(days:int=Query(default=7,ge=1,le=90),admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
    now=datetime.now(timezone.utc)
    a,b=_tenant_usage(db,admin.tenant_id)
    today=now.replace(hour=0,minute=0,second=0,microsecond=0)
    month=now.replace(day=1,hour=0,minute=0,second=0,microsecond=0)
    return {"bytes_in":a,"bytes_out":b,"total_bytes":a+b,
            "today_bytes":_snapshot_delta(db,admin.tenant_id,since=today),
            "month_bytes":_snapshot_delta(db,admin.tenant_id,since=month),
            "window_days":days}

@router.get("/breakdown")
def breakdown(days:int=Query(default=7,ge=1,le=90),protocol:str|None=None,node_id:str|None=None,inbound_id:str|None=None,client_id:str|None=None,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
    q=db.query(TrafficUsage).join(Client,Client.id==TrafficUsage.client_id).join(Inbound,Inbound.id==TrafficUsage.inbound_id).join(Node,Node.id==TrafficUsage.node_id).filter(TrafficUsage.tenant_id==admin.tenant_id)
    if protocol:q=q.filter(Inbound.protocol==protocol)
    if node_id:q=q.filter(TrafficUsage.node_id==node_id)
    if inbound_id:q=q.filter(TrafficUsage.inbound_id==inbound_id)
    if client_id:q=q.filter(TrafficUsage.client_id==client_id)
    rows=q.all()
    names={x.id:x.name for x in db.query(Client).filter(Client.tenant_id==admin.tenant_id).all()}
    protocols={x.id:(x.protocol.value if hasattr(x.protocol,"value") else str(x.protocol)) for x in db.query(Inbound).filter(Inbound.tenant_id==admin.tenant_id).all()}
    out={}
    for r in rows:
        key=r.client_id
        item=out.setdefault(key,{"client_id":r.client_id,"client_name":None,"node_id":r.node_id,"inbound_id":r.inbound_id,"protocol":None,"bytes_in":0,"bytes_out":0})
        item["bytes_in"]+=int(r.bytes_in);item["bytes_out"]+=int(r.bytes_out)
        if item["client_name"] is None:item["client_name"]=names.get(r.client_id,"—")
        item["protocol"]=protocols.get(r.inbound_id,"—")
    result=list(out.values())
    for x in result:x["total_bytes"]=x["bytes_in"]+x["bytes_out"]
    result.sort(key=lambda x:x["total_bytes"],reverse=True)
    return {"days":days,"items":result}

@router.get("/timeseries")
def timeseries(days:int=Query(default=7,ge=1,le=90),admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
    since=datetime.now(timezone.utc)-timedelta(days=days)
    rows=db.query(TrafficSnapshot).filter(TrafficSnapshot.tenant_id==admin.tenant_id,TrafficSnapshot.captured_at>=since).order_by(TrafficSnapshot.captured_at).all()
    buckets=defaultdict(lambda:{"bytes_in":0,"bytes_out":0})
    prev={}
    for r in rows:
        key=r.client_id;cur_in=int(r.bytes_in);cur_out=int(r.bytes_out);old=prev.get(key)
        if old:
            bucket=r.captured_at.astimezone(timezone.utc).strftime("%Y-%m-%d")
            buckets[bucket]["bytes_in"]+=max(0,cur_in-old[0]);buckets[bucket]["bytes_out"]+=max(0,cur_out-old[1])
        prev[key]=(cur_in,cur_out)
    return [{"date":k,"bytes_in":v["bytes_in"],"bytes_out":v["bytes_out"],"total_bytes":v["bytes_in"]+v["bytes_out"]} for k,v in sorted(buckets.items())]
