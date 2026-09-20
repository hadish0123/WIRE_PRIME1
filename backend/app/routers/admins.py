from fastapi import APIRouter,Depends,HTTPException,Request
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_permission
from ..models import Admin,RoleName,Tenant,Inbound,AdminInboundScope,Client
from ..security import hash_password
from ..services.audit import record

router=APIRouter()

def _scope_ids(db,admin_id):
 return [x.inbound_id for x in db.query(AdminInboundScope).filter(AdminInboundScope.admin_id==admin_id).all()]

def _admin_row(db,a):
 scope_ids=_scope_ids(db,a.id)
 client_count=db.query(Client).filter(Client.created_by_admin_id==a.id,Client.tenant_id==a.tenant_id).count()
 return {"id":a.id,"email":a.email,"tenant_id":a.tenant_id,"role":a.role.value,"enabled":a.enabled,"created_at":a.created_at,
         "inbound_ids":scope_ids,"scope_all":len(scope_ids)==0,"own_clients":client_count}

@router.get("")
def list_admins(admin:Admin=Depends(require_permission("admins:read")),db:Session=Depends(get_db)):
 q=db.query(Admin).filter(Admin.role!=RoleName.platform_owner)
 if admin.role!=RoleName.platform_owner:q=q.filter(Admin.tenant_id==admin.tenant_id)
 return [_admin_row(db,a) for a in q.order_by(Admin.created_at.desc()).all()]

@router.get("/permissions")
def permissions(admin:Admin=Depends(current_admin)):
 from ..deps import ROLE_PERMISSIONS
 return {"role":admin.role.value,"permissions":sorted(ROLE_PERMISSIONS.get(admin.role,set()))}

@router.get("/my-inbounds")
def my_inbounds(admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
    if admin.role==RoleName.representative:
        rows=(db.query(Inbound)
              .join(AdminInboundScope,AdminInboundScope.inbound_id==Inbound.id)
              .filter(AdminInboundScope.admin_id==admin.id,Inbound.tenant_id==admin.tenant_id)
              .order_by(Inbound.name.asc()).all())
    else:
        rows=db.query(Inbound).filter(Inbound.tenant_id==admin.tenant_id).order_by(Inbound.name.asc()).all() if admin.tenant_id else db.query(Inbound).order_by(Inbound.name.asc()).all()
    return [{"id":x.id,"name":x.name,"protocol":x.protocol.value,"node_id":x.node_id,"listen_port":x.listen_port,"enabled":x.enabled} for x in rows]

@router.get("/inbounds")
def available_inbounds(admin:Admin=Depends(require_permission("admins:manage")),db:Session=Depends(get_db)):
 if admin.role==RoleName.platform_owner:
  rows=db.query(Inbound).order_by(Inbound.name.asc()).all()
 else:
  rows=db.query(Inbound).filter(Inbound.tenant_id==admin.tenant_id).order_by(Inbound.name.asc()).all()
 return [{"id":x.id,"name":x.name,"protocol":x.protocol.value,"node_id":x.node_id,"listen_port":x.listen_port,"enabled":x.enabled} for x in rows]

@router.post("")
def create_admin(body:dict,request:Request,admin:Admin=Depends(require_permission("admins:manage")),db:Session=Depends(get_db)):
 role=body.get("role",RoleName.tenant_operator.value)
 allowed={RoleName.tenant_manager.value,RoleName.tenant_operator.value,RoleName.representative.value}
 if role not in allowed: raise HTTPException(422,"Invalid role")
 tenant_id=body.get("tenant_id") if admin.role==RoleName.platform_owner else admin.tenant_id
 if not tenant_id or not db.query(Tenant).filter(Tenant.id==tenant_id,Tenant.enabled==True).first():raise HTTPException(404,"Tenant not found")
 email=str(body.get("email","")).lower().strip();password=str(body.get("password",""))
 if len(password)<12 or "@" not in email:raise HTTPException(422,"Invalid admin data")
 if db.query(Admin).filter(Admin.email==email).first():raise HTTPException(409,"Email exists")
 scope_ids=list(dict.fromkeys([str(x) for x in (body.get("inbound_ids") or [])]))
 if role==RoleName.representative and not scope_ids:raise HTTPException(422,"Representative must have at least one allowed inbound")
 if scope_ids:
  rows=db.query(Inbound).filter(Inbound.id.in_(scope_ids),Inbound.tenant_id==tenant_id).all()
  if len(rows)!=len(scope_ids):raise HTTPException(422,"One or more inbound scopes are invalid")
 a=Admin(tenant_id=tenant_id,email=email,password_hash=hash_password(password),role=RoleName(role),enabled=True)
 db.add(a);db.flush()
 for inbound_id in scope_ids:db.add(AdminInboundScope(admin_id=a.id,inbound_id=inbound_id))
 record(db,admin,request,"admin.create","admin",a.id)
 db.commit();db.refresh(a)
 return _admin_row(db,a)

@router.patch("/{admin_id}")
def update_admin(admin_id:str,body:dict,request:Request,admin:Admin=Depends(require_permission("admins:manage")),db:Session=Depends(get_db)):
 target=db.query(Admin).filter(Admin.id==admin_id).first()
 if not target or target.role==RoleName.platform_owner:raise HTTPException(404,"Admin not found")
 if admin.role!=RoleName.platform_owner and target.tenant_id!=admin.tenant_id:raise HTTPException(404,"Admin not found")
 if target.id==admin.id and body.get("enabled") is False:raise HTTPException(422,"You cannot disable your own account")
 role=body.get("role")
 if role is not None:
  if role not in {x.value for x in (RoleName.tenant_manager,RoleName.tenant_operator,RoleName.representative)}:raise HTTPException(422,"Invalid role")
  target.role=RoleName(role)
 scope_ids=body.get("inbound_ids")
 if scope_ids is not None:
  scope_ids=list(dict.fromkeys([str(x) for x in scope_ids]))
  if target.role==RoleName.representative and not scope_ids:raise HTTPException(422,"Representative must have at least one allowed inbound")
  rows=db.query(Inbound).filter(Inbound.id.in_(scope_ids),Inbound.tenant_id==target.tenant_id).all() if scope_ids else []
  if len(rows)!=len(scope_ids):raise HTTPException(422,"Invalid inbound scope")
  db.query(AdminInboundScope).filter(AdminInboundScope.admin_id==target.id).delete(synchronize_session=False)
  for inbound_id in scope_ids:db.add(AdminInboundScope(admin_id=target.id,inbound_id=inbound_id))
 if "enabled" in body:target.enabled=bool(body["enabled"])
 if body.get("password"):
  p=str(body["password"])
  if len(p)<12:raise HTTPException(422,"Password must be at least 12 characters")
  target.password_hash=hash_password(p)
 record(db,admin,request,"admin.update","admin",target.id)
 db.commit();db.refresh(target)
 return _admin_row(db,target)

@router.delete("/{admin_id}")
def disable_admin(admin_id:str,request:Request,admin:Admin=Depends(require_permission("admins:manage")),db:Session=Depends(get_db)):
 target=db.query(Admin).filter(Admin.id==admin_id).first()
 if not target or target.role==RoleName.platform_owner:raise HTTPException(404,"Admin not found")
 if admin.role!=RoleName.platform_owner and target.tenant_id!=admin.tenant_id:raise HTTPException(404,"Admin not found")
 if target.id==admin.id:raise HTTPException(422,"You cannot disable your own account")
 target.enabled=False
 record(db,admin,request,"admin.disable","admin",target.id)
 db.commit()
 return {"status":"disabled","id":target.id}
