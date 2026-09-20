from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin
from ..models import Admin,Inbound,Node
from ..schemas import InboundIn,InboundOut
router=APIRouter()
@router.get("",response_model=list[InboundOut])
def list_inbounds(admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 return db.query(Inbound).filter(Inbound.tenant_id==admin.tenant_id).order_by(Inbound.created_at.desc()).all()
@router.post("",response_model=InboundOut)
def create_inbound(data:InboundIn,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 node=db.query(Node).filter(Node.id==data.node_id,Node.tenant_id==admin.tenant_id).first()
 if not node:raise HTTPException(404,"Node not found")
 item=Inbound(tenant_id=admin.tenant_id,**data.model_dump());db.add(item);db.commit();db.refresh(item);return item
@router.patch("/{inbound_id}",response_model=InboundOut)
def update_inbound(inbound_id:str,data:InboundIn,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 item=db.query(Inbound).filter(Inbound.id==inbound_id,Inbound.tenant_id==admin.tenant_id).first()
 if not item:raise HTTPException(404,"Inbound not found")
 for k,v in data.model_dump().items():setattr(item,k,v)
 db.commit();db.refresh(item);return item