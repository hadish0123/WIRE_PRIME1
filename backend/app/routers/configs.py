from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..deps import current_admin,require_tenant_manager,can_access_client
from ..models import Admin,Client,Protocol
from ..services.config_artifacts import create_artifact,read_artifact
router=APIRouter()
@router.post("/clients/{client_id}")
def generate(client_id:str,protocol:Protocol,payload:str,admin:Admin=Depends(require_tenant_manager),db:Session=Depends(get_db)):
 c=db.query(Client).filter(Client.id==client_id,Client.tenant_id==admin.tenant_id).first()
 if not c:raise HTTPException(404,"Client not found")
 a=create_artifact(db,c,protocol,payload)
 return {"id":a.id,"fingerprint":a.fingerprint,"expires_at":a.expires_at}
@router.get("/{artifact_id}")
def download(artifact_id:str,admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):
 from ..models import ConfigArtifact
 a=db.query(ConfigArtifact).filter(ConfigArtifact.id==artifact_id,ConfigArtifact.tenant_id==admin.tenant_id).first()
 if not a:raise HTTPException(404,"Artifact not found")
 try:payload=read_artifact(a)
 except ValueError as e:raise HTTPException(410,str(e))
 a.downloaded_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc);db.commit()
 return {"protocol":a.protocol,"payload":payload,"fingerprint":a.fingerprint}
