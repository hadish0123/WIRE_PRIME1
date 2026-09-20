from fastapi import Depends,HTTPException,Request
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .db import get_db
from .security import decode_access_token
from .models import Admin,RoleName
bearer=HTTPBearer(auto_error=False)
def current_admin(request:Request,creds:HTTPAuthorizationCredentials|None=Depends(bearer),db:Session=Depends(get_db)):
 if not creds:raise HTTPException(401,"Authentication required")
 try:p=decode_access_token(creds.credentials)
 except Exception:raise HTTPException(401,"Invalid or expired token")
 a=db.get(Admin,p["sub"])
 if not a or not a.enabled:raise HTTPException(401,"Account disabled")
 request.state.tenant_id=a.tenant_id;request.state.admin_id=a.id;return a
def require_platform(admin:Admin=Depends(current_admin)):
 if admin.role!=RoleName.platform_owner:raise HTTPException(403,"Platform permission required")
 return admin