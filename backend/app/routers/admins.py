from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin
from ..models import Admin,RoleName
from ..security import hash_password
router=APIRouter()
@router.get("")
def list_admins(admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 q=db.query(Admin).filter(Admin.tenant_id==admin.tenant_id)
 return q.order_by(Admin.created_at.desc()).all()
@router.post("")
def create_admin(body:dict,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 role=body.get("role",RoleName.tenant_operator.value)
 if role not in {RoleName.tenant_manager.value,RoleName.tenant_operator.value}:raise HTTPException(403,"Role exceeds tenant scope")
 email=str(body.get("email","")).lower().strip();password=str(body.get("password",""))
 if len(password)<12 or "@" not in email:raise HTTPException(422,"Invalid admin data")
 if db.query(Admin).filter(Admin.email==email).first():raise HTTPException(409,"Email exists")
 a=Admin(tenant_id=admin.tenant_id,email=email,password_hash=hash_password(password),role=RoleName(role));db.add(a);db.commit();db.refresh(a);return {"id":a.id,"email":a.email,"role":a.role}