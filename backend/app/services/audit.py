import json
from ..models import AuditLog
def record(db,admin,request,action,resource,resource_id=None,result="SUCCESS",details=None):
 db.add(AuditLog(tenant_id=admin.tenant_id,actor_id=admin.id,action=action,resource=resource,resource_id=resource_id,result=result,ip=request.client.host if request.client else None,user_agent=request.headers.get("user-agent"),request_id=getattr(request.state,"request_id",None),details=json.dumps(details or {},separators=(",",":"))))
