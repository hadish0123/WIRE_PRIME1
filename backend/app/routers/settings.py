from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import require_permission
from ..models import Admin, Tenant, TenantSettings
router=APIRouter()

def _row(x):
 return {"tenant_id":x.tenant_id,"panel_name":x.panel_name,"timezone":x.timezone,"language":x.language,"default_protocol":x.default_protocol,"default_dns":x.default_dns,"default_client_quota_gb":x.default_client_quota_gb,"default_client_duration_days":x.default_client_duration_days,"session_timeout_minutes":x.session_timeout_minutes,"audit_retention_days":x.audit_retention_days,"require_mfa":x.require_mfa,"updated_at":x.updated_at.isoformat() if x.updated_at else None}

def _get(db,tenant_id):
 x=db.query(TenantSettings).filter(TenantSettings.tenant_id==tenant_id).first()
 if not x:
  x=TenantSettings(tenant_id=tenant_id);db.add(x);db.commit();db.refresh(x)
 return x

@router.get("")
def get_settings(admin:Admin=Depends(require_permission("settings:read")),db:Session=Depends(get_db)):
 if not admin.tenant_id: raise HTTPException(400,"Tenant context required")
 tenant=db.get(Tenant,admin.tenant_id); x=_get(db,admin.tenant_id)
 return {"settings":_row(x),"tenant":{"id":tenant.id,"name":tenant.name,"slug":tenant.slug,"enabled":tenant.enabled} if tenant else None}

@router.patch("")
def update_settings(body:dict,admin:Admin=Depends(require_permission("settings:write")),db:Session=Depends(get_db)):
 if not admin.tenant_id: raise HTTPException(400,"Tenant context required")
 x=_get(db,admin.tenant_id)
 allowed={"panel_name":"str","timezone":"str","language":"str","default_protocol":"str","default_dns":"str","default_client_quota_gb":"int","default_client_duration_days":"int","session_timeout_minutes":"int","audit_retention_days":"int","require_mfa":"bool"}
 for key,kind in allowed.items():
  if key not in body: continue
  v=body[key]
  if kind=="str": v=str(v).strip()
  elif kind=="int":
   try:v=int(v)
   except: raise HTTPException(422,f"Invalid {key}")
   if v<0: raise HTTPException(422,f"{key} must be non-negative")
  else:v=bool(v)
  setattr(x,key,v)
 if x.language not in {"fa","en"}: raise HTTPException(422,"language must be fa or en")
 if x.default_protocol not in {"wireguard","amneziawg","openvpn"}: raise HTTPException(422,"Unsupported default protocol")
 if not x.panel_name or len(x.panel_name)>160: raise HTTPException(422,"Invalid panel name")
 x.updated_at=datetime.now(timezone.utc);db.commit();db.refresh(x)
 return {"ok":True,"settings":_row(x)}
