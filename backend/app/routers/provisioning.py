from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin
from ..models import Admin,Node,ProvisioningTask,NodeState
from ..services.reconcile import desired_node_state
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
