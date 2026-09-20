from fastapi import APIRouter,Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..db import get_db
from ..deps import current_admin
from ..models import Admin,TrafficUsage
router=APIRouter()
@router.get("/summary")
def summary(admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 a,b=db.query(func.coalesce(func.sum(TrafficUsage.bytes_in),0),func.coalesce(func.sum(TrafficUsage.bytes_out),0)).filter(TrafficUsage.tenant_id==admin.tenant_id).one()
 return {"bytes_in":int(a),"bytes_out":int(b),"total_bytes":int(a+b)}