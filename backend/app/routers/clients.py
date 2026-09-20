from fastapi import APIRouter,Depends,HTTPException
from ..services.audit import record
from fastapi import Request
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin
from ..models import Admin,Client,Inbound,ResourceState
from ..schemas import ClientIn,ClientOut
router=APIRouter()
@router.get("",response_model=list[ClientOut])
def list_clients(admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 return db.query(Client).filter(Client.tenant_id==admin.tenant_id).order_by(Client.created_at.desc()).all()
@router.post("",response_model=ClientOut)
def create_client(data:ClientIn,request:Request,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 inbound=db.query(Inbound).filter(Inbound.id==data.inbound_id,Inbound.tenant_id==admin.tenant_id).first()
 if not inbound:raise HTTPException(404,"Inbound not found")
 c=Client(tenant_id=admin.tenant_id,**data.model_dump());db.add(c);record(db,admin,request,"client.create","client",c.id);db.commit();db.refresh(c);return c
@router.post("/{client_id}/revoke")
def revoke(client_id:str,request:Request,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 c=db.query(Client).filter(Client.id==client_id,Client.tenant_id==admin.tenant_id).first()
 if not c:raise HTTPException(404,"Client not found")
 c.status=ResourceState.revoked;record(db,admin,request,"client.revoke","client",c.id);db.commit();return {"status":"revoked","client_id":c.id}