import base64,hashlib
from datetime import datetime,timezone,timedelta
from ..models import ConfigArtifact
def create_artifact(db,client,protocol,payload,ttl_minutes=60):
 raw=payload.encode();fp=hashlib.sha256(raw).hexdigest();exp=datetime.now(timezone.utc)+timedelta(minutes=ttl_minutes)
 item=ConfigArtifact(tenant_id=client.tenant_id,client_id=client.id,protocol=protocol,fingerprint=fp,encrypted_payload=base64.b64encode(raw).decode(),expires_at=exp)
 db.add(item);db.commit();db.refresh(item);return item
def read_artifact(item):
 if item.expires_at<=datetime.now(timezone.utc):raise ValueError("Artifact expired")
 return base64.b64decode(item.encrypted_payload).decode()
