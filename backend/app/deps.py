from fastapi import Depends,HTTPException,Request
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime,timezone,timedelta
from .db import get_db,set_platform_context,set_tenant_context
from .security import decode_access_token
from .models import Admin,RoleName,Client,AdminInboundScope,TrafficUsage

bearer=HTTPBearer(auto_error=False)

ROLE_PERMISSIONS={
 RoleName.platform_owner:{"*"},
 RoleName.tenant_manager:{
  "admins:read","admins:manage","roles:read","roles:manage",
  "nodes:read","nodes:create","nodes:provision","nodes:update",
  "inbounds:read","inbounds:create","inbounds:update","inbounds:delete",
  "clients:read","clients:create","clients:update","clients:revoke",
  "traffic:read","quota:read","quota:manage","audit:read","settings:read","settings:write"
 },
 RoleName.tenant_operator:{
  "nodes:read","inbounds:read","clients:read","traffic:read","quota:read","audit:read"
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
    state,_,_=admin_quota_state(db,a)
    if state=="EXPIRED":
        raise HTTPException(403,"Admin access period expired")
    return a

def admin_quota_usage(db:Session,admin:Admin)->int:
    if admin.role==RoleName.platform_owner:
        return 0
    value=(db.query(func.coalesce(func.sum(TrafficUsage.bytes_in+TrafficUsage.bytes_out),0))
           .join(Client,Client.id==TrafficUsage.client_id)
           .filter(Client.tenant_id==admin.tenant_id,Client.created_by_admin_id==admin.id)
           .scalar())
    return int(value or 0)

def admin_quota_state(db:Session,admin:Admin):
    if admin.role==RoleName.platform_owner:
        return "NORMAL",0,None
    now=datetime.now(timezone.utc)
    started=admin.quota_started_at
    if started and started.tzinfo is None:
        started=started.replace(tzinfo=timezone.utc)
    days=int(admin.quota_duration_days or 0)
    expires=started+timedelta(days=days) if started and days>0 else None
    used=admin_quota_usage(db,admin)
    if expires and expires<=now:
        return "EXPIRED",used,expires
    limit=int(admin.traffic_limit_bytes or 0)
    if limit>0 and used>=limit:
        return "LIMIT_REACHED",used,expires
    if limit>0 and used>=limit*0.8:
        return "WARNING",used,expires
    return "NORMAL",used,expires

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


def can_access_client(db:Session,admin:Admin,client:Client)->bool:
    if not client:
        return False
    if admin.role==RoleName.platform_owner:
        return True
    if client.tenant_id!=admin.tenant_id:
        return False
    if admin.role==RoleName.representative:
        return client.created_by_admin_id==admin.id
    return True

def representative_can_use_inbound(db:Session,admin:Admin,inbound_id:str)->bool:
    if admin.role!=RoleName.representative:
        return True
    return db.query(AdminInboundScope).filter(
        AdminInboundScope.admin_id==admin.id,
        AdminInboundScope.inbound_id==inbound_id
    ).first() is not None
