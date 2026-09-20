from fastapi import APIRouter,Depends,HTTPException,Request
from datetime import datetime,timezone,timedelta
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_tenant_manager
from ..models import Admin,Node,NodeState,ProvisioningTask
from ..schemas import NodeIn,NodeOut
from ..services.audit import record
from ..security import new_bootstrap_token
router=APIRouter()
@router.get("",response_model=list[NodeOut])
def list_nodes(admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 return db.query(Node).filter(Node.tenant_id==admin.tenant_id).order_by(Node.created_at.desc()).all()
@router.post("",response_model=NodeOut)
def create_node(data:NodeIn,request:Request,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 if not admin.tenant_id:raise HTTPException(400,"Tenant required")
 n=Node(tenant_id=admin.tenant_id,name=data.name,address=data.address,agent_url=data.agent_url);db.add(n);record(db,admin,request,"node.create","node",n.id);db.commit();db.refresh(n);return n
@router.post("/{node_id}/provision")
def provision(node_id:str,request:Request,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 n=db.query(Node).filter(Node.id==node_id,Node.tenant_id==admin.tenant_id).first()
 if not n:raise HTTPException(404,"Node not found")
 key=request.headers.get("Idempotency-Key")
 if not key:raise HTTPException(400,"Idempotency-Key required")
 old=db.query(ProvisioningTask).filter(ProvisioningTask.idempotency_key==key).first()
 if old:return {"task_id":old.id,"state":old.state}
 raw,h=new_bootstrap_token()
 t=ProvisioningTask(tenant_id=admin.tenant_id,node_id=n.id,idempotency_key=key,state=NodeState.authenticating.value,bootstrap_token_hash=h,bootstrap_expires_at=datetime.now(timezone.utc)+timedelta(minutes=15))
 n.state=NodeState.authenticating;db.add(t);record(db,admin,request,"node.provision","node",n.id,details={"task_id":t.id});db.commit()
 return {"task_id":t.id,"state":t.state,"bootstrap_token":raw,"expires_at":t.bootstrap_expires_at}
@router.get("/{node_id}/health")
def health(node_id:str,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 n=db.query(Node).filter(Node.id==node_id,Node.tenant_id==admin.tenant_id).first()
 if not n:raise HTTPException(404,"Node not found")
 return {"node_id":n.id,"state":n.state,"last_seen_at":n.last_seen_at}
