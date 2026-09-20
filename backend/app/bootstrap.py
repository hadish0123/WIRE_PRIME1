import os
from .db import SessionLocal,set_platform_context
from .models import Admin,RoleName
from .security import hash_password
def main():
 email=os.environ.get("PRIMEVPN_BOOTSTRAP_EMAIL","").strip().lower()
 password=os.environ.get("PRIMEVPN_BOOTSTRAP_PASSWORD","")
 if not email or len(password)<16:raise SystemExit("Set PRIMEVPN_BOOTSTRAP_EMAIL and a password of at least 16 characters")
 db=SessionLocal()
 try:
  set_platform_context(db)
  existing=db.query(Admin).filter(Admin.email==email).first()
  if existing:
   print("bootstrap admin already exists")
   return
  admin=Admin(tenant_id=None,email=email,password_hash=hash_password(password),role=RoleName.platform_owner,enabled=True)
  db.add(admin);db.commit();print("platform owner created")
 finally:db.close()
if __name__=="__main__":main()
