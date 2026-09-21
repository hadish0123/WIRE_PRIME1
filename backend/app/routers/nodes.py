from fastapi import APIRouter,Depends,HTTPException,Request
from datetime import datetime,timezone,timedelta
import ipaddress
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_tenant_manager,require_permission
from ..models import Admin,Node,NodeState,ProvisioningTask,Inbound
from ..schemas import NodeIn,NodeOut,AutoNodeIn
from ..services.ssh_provisioner import install_node_agent,verify_agent,SSHProvisionError
import json
from ..services.audit import record
from ..security import new_bootstrap_token,create_agent_token
from ..config import settings
router=APIRouter()

@router.get("",response_model=list[NodeOut])
def list_nodes(admin:Admin=Depends(require_permission("nodes:read")),db:Session=Depends(get_db)):
 return db.query(Node).filter(Node.tenant_id==admin.tenant_id).order_by(Node.created_at.desc()).all()

@router.post("",response_model=NodeOut)
def create_node(data:NodeIn,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 if not admin.tenant_id: raise HTTPException(400,"Tenant required")
 if settings.environment=="production" and data.agent_url and not data.agent_url.startswith("https://"): raise HTTPException(422,"Production Node Agent URL must use HTTPS")
 n=Node(tenant_id=admin.tenant_id,name=data.name,address=data.address,agent_url=data.agent_url)
 db.add(n);db.flush();record(db,admin,request,"node.create","node",n.id);db.commit();db.refresh(n);return n

@router.post("/install-token")
def install_token(data:NodeIn,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 if not admin.tenant_id: raise HTTPException(400,"Tenant required")
 if not settings.agent_verify_public_key: raise HTTPException(503,"Agent verification key is not configured")
 n=Node(tenant_id=admin.tenant_id,name=data.name,address=data.address,agent_url=None,state=NodeState.authenticating)
 db.add(n);db.flush()
 raw,h=new_bootstrap_token()
 task=ProvisioningTask(tenant_id=admin.tenant_id,node_id=n.id,idempotency_key="install:"+raw,state=NodeState.authenticating.value,bootstrap_token_hash=h,bootstrap_expires_at=datetime.now(timezone.utc)+timedelta(minutes=15))
 db.add(task);db.flush()
 record(db,admin,request,"node.install_token","node",n.id,details={"task_id":task.id})
 db.commit()
 from shlex import quote
 backend=str(request.base_url).rstrip("/")
 installer=backend+"/api/v1/provisioning/install.sh"
 command=f"curl -fsSL {quote(installer)} | sudo bash -s -- {quote(backend)} {quote(task.id)} {quote(raw)} {quote(data.address)}"
 return {"node_id":n.id,"task_id":task.id,"bootstrap_token":raw,"expires_at":task.bootstrap_expires_at,"install_command":command,"installer_url":installer}

@router.post("/auto-provision")
async def auto_provision(data:AutoNodeIn,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 if not admin.tenant_id: raise HTTPException(400,"Tenant required")
 if not settings.agent_verify_public_key: raise HTTPException(503,"Agent verification key is not configured")
 n=Node(tenant_id=admin.tenant_id,name=data.name,address=data.address,agent_url=None,state=NodeState.installing)
 db.add(n);db.flush();record(db,admin,request,"node.auto_provision.start","node",n.id,details={"address":data.address});db.commit()
 try:
  result=await install_node_agent(data.address,data.ssh_port,data.ssh_username,data.ssh_password,n.id,settings.agent_verify_public_key)
  agent_url=(f"https://{data.address}:{result['agent_port']}" if result['agent_port']!=443 else f"https://{data.address}")
  n.agent_url=agent_url
  token=create_agent_token(n.id,n.tenant_id,["read","write"])
  health=await verify_agent(agent_url,token)
  n.state=NodeState.ready
  n.agent_version=health.get("version")
  n.capabilities=json.dumps(health.get("capabilities") or {},separators=(",",":"))
  n.last_seen_at=datetime.now(timezone.utc)
  db.commit();db.refresh(n)
  record(db,admin,request,"node.auto_provision.ready","node",n.id,details={"agent_url":agent_url})
  db.commit()
  return {"node":n,"agent_url":agent_url,"status":"READY","capabilities":health.get("capabilities") or {}}
 except SSHProvisionError as e:
  n.state=NodeState.provision_failed
  db.commit()
  raise HTTPException(502,str(e))
 except Exception as e:
  n.state=NodeState.provision_failed
  db.commit()
  raise HTTPException(502,f"Automatic Node provisioning failed: {e}")

@router.delete("/{node_id}")
def delete_node(node_id:str,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 n=db.query(Node).filter(Node.id==node_id,Node.tenant_id==admin.tenant_id).first()
 if not n: raise HTTPException(404,"Node not found")
 if db.query(Inbound).filter(Inbound.node_id==n.id,Inbound.tenant_id==admin.tenant_id).first():
  raise HTTPException(409,"Cannot delete a Node that still has Inbounds. Remove its Inbounds first.")
 name=n.name
 db.delete(n);db.commit()
 record(db,admin,request,"node.delete","node",node_id,details={"name":name});db.commit()
 return {"status":"DELETED","node_id":node_id}

@router.post("/{node_id}/provision")
def provision(node_id:str,request:Request,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 n=db.query(Node).filter(Node.id==node_id,Node.tenant_id==admin.tenant_id).first()
 if not n: raise HTTPException(404,"Node not found")
 key=request.headers.get("Idempotency-Key")
 if not key: raise HTTPException(400,"Idempotency-Key required")
 old=db.query(ProvisioningTask).filter(ProvisioningTask.idempotency_key==key,ProvisioningTask.tenant_id==admin.tenant_id).first()
 if old:return {"task_id":old.id,"state":old.state}
 raw,h=new_bootstrap_token()
 t=ProvisioningTask(tenant_id=admin.tenant_id,node_id=n.id,idempotency_key=key,state=NodeState.authenticating.value,bootstrap_token_hash=h,bootstrap_expires_at=datetime.now(timezone.utc)+timedelta(minutes=15))
 n.state=NodeState.authenticating;db.add(t);db.flush();record(db,admin,request,"node.provision","node",n.id,details={"task_id":t.id});db.commit()
 return {"task_id":t.id,"state":t.state,"bootstrap_token":raw,"expires_at":t.bootstrap_expires_at}

@router.get("/{node_id}/health")
def health(node_id:str,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 n=db.query(Node).filter(Node.id==node_id,Node.tenant_id==admin.tenant_id).first()
 if not n:raise HTTPException(404,"Node not found")
 return {"node_id":n.id,"state":n.state,"last_seen_at":n.last_seen_at,"capabilities":n.capabilities}
