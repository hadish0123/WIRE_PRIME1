from fastapi import Depends,HTTPException,Request
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .db import get_db,set_platform_context,set_tenant_context
from .security import decode_access_token
from .models import Admin,RoleName

bearer=HTTPBearer(auto_error=False)

ROLE_PERMISSIONS={
 RoleName.platform_owner:{"*"},
 RoleName.tenant_manager:{
  "admins:read","admins:manage","roles:read","roles:manage",
  "nodes:read","nodes:create","nodes:provision","nodes:update",
  "inbounds:read","inbounds:create","inbounds:update","inbounds:delete",
  "clients:read","clients:create","clients:update","clients:revoke",
  "traffic:read","quota:manage","audit:read"
 },
 RoleName.tenant_operator:{
  "nodes:read","inbounds:read","clients:read","traffic:read","audit:read"
 },
 RoleName.representative:{
  "clients:read","clients:create","clients:update","clients:revoke"
 },
 RoleName.client:set(),
}

def current_admin(
    request:Request,
    creds:HTTPAuthorizationCredentials|None=Depends(bearer),
    db:Session=Depends(get_db),
):
    if not creds:
        raise HTTPException(401,"Authentication required")
    try:
        p=decode_access_token(creds.credentials)
    except Exception:
        raise HTTPException(401,"Invalid or expired token")
    a=db.get(Admin,p["sub"])
    if not a or not a.enabled:
        raise HTTPException(401,"Account disabled")
    request.state.tenant_id=a.tenant_id
    request.state.admin_id=a.id
    if a.role==RoleName.platform_owner:
        set_platform_context(db)
    elif a.tenant_id:
        set_tenant_context(db,a.tenant_id)
    else:
        raise HTTPException(403,"Tenant context required")
    return a

def has_permission(admin:Admin,permission:str)->bool:
    perms=ROLE_PERMISSIONS.get(admin.role,set())
    return "*" in perms or permission in perms

def require_permission(permission:str):
    def dependency(admin:Admin=Depends(current_admin)):
        if not has_permission(admin,permission):
            raise HTTPException(403,"Permission required: "+permission)
        return admin
    return dependency

def require_tenant_manager(admin:Admin=Depends(current_admin)):
    if not has_permission(admin,"admins:manage") and not has_permission(admin,"clients:create"):
        raise HTTPException(403,"Insufficient permission")
    return admin

def require_platform(admin:Admin=Depends(current_admin)):
    if admin.role!=RoleName.platform_owner:
        raise HTTPException(403,"Platform permission required")
    return admin
