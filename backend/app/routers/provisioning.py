from datetime import datetime,timezone,timedelta
from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin
from ..models import Admin,Node,ProvisioningTask,NodeState
from ..services.reconcile import desired_node_state
from ..security import new_bootstrap_token,hash_token,create_agent_token
router=APIRouter()
@router.get("/{node_id}/desired-state")
def desired(node_id:str,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 n=db.query(Node).filter(Node.id==node_id,Node.tenant_id==admin.tenant_id).first()
 if not n:raise HTTPException(404,"Node not found")
 return desired_node_state(db,n)
@router.get("/{node_id}/tasks")
def tasks(node_id:str,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 if not db.query(Node).filter(Node.id==node_id,Node.tenant_id==admin.tenant_id).first():raise HTTPException(404,"Node not found")
 return db.query(ProvisioningTask).filter(ProvisioningTask.node_id==node_id,ProvisioningTask.tenant_id==admin.tenant_id).order_by(ProvisioningTask.created_at.desc()).limit(100).all()
@router.post("/{node_id}/bootstrap")
def bootstrap(node_id:str,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 n=db.query(Node).filter(Node.id==node_id,Node.tenant_id==admin.tenant_id).first()
 if not n:raise HTTPException(404,"Node not found")
 raw,h=new_bootstrap_token()
 task=ProvisioningTask(tenant_id=admin.tenant_id,node_id=n.id,idempotency_key="bootstrap:"+raw,state=NodeState.authenticating.value,bootstrap_token_hash=h,bootstrap_expires_at=datetime.now(timezone.utc)+timedelta(minutes=15))
 db.add(task);n.state=NodeState.authenticating;db.commit()
 return {"task_id":task.id,"bootstrap_token":raw,"expires_at":task.bootstrap_expires_at}
@router.post("/bootstrap/{task_id}/exchange")
def exchange(task_id:str,token:str,db:Session=Depends(get_db)):
 task=db.query(ProvisioningTask).filter(ProvisioningTask.id==task_id).first()
 if not task or not task.bootstrap_token_hash or not task.bootstrap_expires_at or task.bootstrap_expires_at<=datetime.now(timezone.utc):raise HTTPException(401,"Bootstrap token expired")
 if hash_token(token)!=task.bootstrap_token_hash:raise HTTPException(401,"Invalid bootstrap token")
 node=db.query(Node).filter(Node.id==task.node_id).first()
 task.bootstrap_token_hash=None;task.bootstrap_expires_at=None;task.state=NodeState.syncing.value;node.state=NodeState.syncing
 db.commit()
 return {"node_id":node.id,"tenant_id":node.tenant_id,"agent_token":create_agent_token(node.id,node.tenant_id,["read","write"]),"expires_in":600}
