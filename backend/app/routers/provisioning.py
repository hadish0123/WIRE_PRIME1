from datetime import datetime,timezone,timedelta
from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel,Field
from sqlalchemy.orm import Session
from ..db import get_db,set_platform_context
from ..deps import current_admin,require_tenant_manager
from ..models import Admin,Node,ProvisioningTask,NodeState
from ..services.reconcile import desired_node_state
from ..security import new_bootstrap_token,hash_token,create_agent_token,decode_agent_token
router=APIRouter()
class BootstrapExchange(BaseModel):
 token:str=Field(min_length=30,max_length=256)

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
def bootstrap(node_id:str,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 n=db.query(Node).filter(Node.id==node_id,Node.tenant_id==admin.tenant_id).first()
 if not n:raise HTTPException(404,"Node not found")
 raw,h=new_bootstrap_token()
 task=ProvisioningTask(tenant_id=admin.tenant_id,node_id=n.id,idempotency_key="bootstrap:"+raw,state=NodeState.authenticating.value,bootstrap_token_hash=h,bootstrap_expires_at=datetime.now(timezone.utc)+timedelta(minutes=15))
 db.add(task);n.state=NodeState.authenticating;db.commit()
 return {"task_id":task.id,"bootstrap_token":raw,"expires_at":task.bootstrap_expires_at}

@router.post("/bootstrap/{task_id}/exchange")
def exchange(task_id:str,body:BootstrapExchange,db:Session=Depends(get_db)):
 set_platform_context(db)
 task=db.query(ProvisioningTask).filter(ProvisioningTask.id==task_id).with_for_update().first()
 now=datetime.now(timezone.utc)
 if not task or not task.bootstrap_token_hash or not task.bootstrap_expires_at or task.bootstrap_expires_at<=now:raise HTTPException(401,"Bootstrap token expired")
 if hash_token(body.token)!=task.bootstrap_token_hash:raise HTTPException(401,"Invalid bootstrap token")
 node=db.query(Node).filter(Node.id==task.node_id,Node.tenant_id==task.tenant_id).first()
 if not node:raise HTTPException(401,"Invalid bootstrap binding")
 task.bootstrap_token_hash=None;task.bootstrap_expires_at=None;task.state=NodeState.syncing.value;node.state=NodeState.syncing;db.commit()
 return {"node_id":node.id,"tenant_id":node.tenant_id,"agent_token":create_agent_token(node.id,node.tenant_id,["read","write"]),"expires_in":600}


class AgentRegistration(BaseModel):
 agent_url:str=Field(min_length=10,max_length=512)
 version:str|None=Field(default=None,max_length=40)
 capabilities:dict=Field(default_factory=dict)

@router.post("/{node_id}/register")
async def register_agent(node_id:str,body:AgentRegistration,request:Request,db:Session=Depends(get_db)):
 token=request.headers.get("Authorization","")
 if not token.lower().startswith("bearer "): raise HTTPException(401,"Agent token required")
 try: claims=decode_agent_token(token[7:].strip())
 except Exception: raise HTTPException(401,"Invalid agent token")
 if claims.get("type")!="node_access" or claims.get("sub")!=node_id: raise HTTPException(403,"Agent identity mismatch")
 node=db.query(Node).filter(Node.id==node_id,Node.tenant_id==claims.get("tenant_id")).first()
 if not node: raise HTTPException(404,"Node not found")
 node.agent_url=body.agent_url
 node.agent_version=body.version
 import json
 node.capabilities=json.dumps(body.capabilities or {},separators=(",",":"))
 node.state=NodeState.ready
 node.last_seen_at=datetime.now(timezone.utc)
 db.commit()
 return {"status":"READY","node_id":node.id}
