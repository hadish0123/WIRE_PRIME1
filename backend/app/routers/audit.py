from fastapi import APIRouter,Depends
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin
from ..models import Admin,AuditLog
router=APIRouter()
@router.get("")
def list_audit(admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 return db.query(AuditLog).filter(AuditLog.tenant_id==admin.tenant_id).order_by(AuditLog.created_at.desc()).limit(200).all()