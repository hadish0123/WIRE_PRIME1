import hashlib
from datetime import datetime,timezone,timedelta
from ..models import ConfigArtifact
from ..security import encrypt_secret,decrypt_secret

def create_artifact(db,client,protocol,payload,ttl_minutes=60):
 raw=payload.encode()
 fp=hashlib.sha256(raw).hexdigest()
 exp=datetime.now(timezone.utc)+timedelta(minutes=ttl_minutes)
 existing=db.query(ConfigArtifact).filter(
  ConfigArtifact.tenant_id==client.tenant_id,
  ConfigArtifact.client_id==client.id,
  ConfigArtifact.protocol==protocol,
  ConfigArtifact.fingerprint==fp,
 ).first()
 if existing:
  existing.encrypted_payload=encrypt_secret(payload)
  existing.expires_at=exp
  existing.downloaded_at=None
  db.commit()
  db.refresh(existing)
  return existing
 item=ConfigArtifact(tenant_id=client.tenant_id,client_id=client.id,protocol=protocol,fingerprint=fp,encrypted_payload=encrypt_secret(payload),expires_at=exp)
 db.add(item)
 db.commit()
 db.refresh(item)
 return item

def read_artifact(item):
 if item.expires_at<=datetime.now(timezone.utc):raise ValueError("Artifact expired")
 payload=decrypt_secret(item.encrypted_payload)
 if hashlib.sha256(payload.encode()).hexdigest()!=item.fingerprint:raise ValueError("Artifact integrity check failed")
 return payload
