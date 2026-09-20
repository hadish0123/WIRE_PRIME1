from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_platform
from ..models import Admin,Tenant,RoleName
from ..schemas import TenantIn
router=APIRouter()
@router.get("")
def list_tenants(admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 q=db.query(Tenant)
 if admin.role!=RoleName.platform_owner:q=q.filter(Tenant.id==admin.tenant_id)
 return q.order_by(Tenant.created_at.desc()).all()
@router.post("")
def create_tenant(data:TenantIn,admin:Admin=Depends(require_platform),db:Session=Depends(get_db)):
 if db.query(Tenant).filter(Tenant.slug==data.slug).first():raise HTTPException(409,"Tenant slug exists")
 t=Tenant(name=data.name,slug=data.slug);db.add(t);db.commit();db.refresh(t);return t