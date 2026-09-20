from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..schemas import LoginIn,TokenOut,MeOut
from ..models import Admin
from ..security import verify_password,create_access_token,decode_access_token,new_totp_secret,totp_uri,verify_totp,encrypt_secret,decrypt_secret
from ..deps import current_admin
from ..config import settings
router=APIRouter()
@router.post("/login",response_model=TokenOut)
def login(data:LoginIn,db:Session=Depends(get_db)):
 a=db.query(Admin).filter(Admin.email==data.email.lower()).first()
 if not a or not verify_password(data.password,a.password_hash):raise HTTPException(401,"Invalid credentials")
 if a.mfa_secret_encrypted:\n  challenge=create_access_token(a.id,a.tenant_id,"mfa")\n  return TokenOut(access_token="",expires_in=settings.access_token_minutes*60,mfa_required=True,mfa_token=challenge)\n return TokenOut(access_token=create_access_token(a.id,a.tenant_id,a.role.value),expires_in=settings.access_token_minutes*60)
@router.get("/me",response_model=MeOut)
def me(admin:Admin=Depends(current_admin)):return admin
@router.post("/mfa/setup")\ndef mfa_setup(admin:Admin=Depends(current_admin),db:Session=Depends(get_db)):\n secret=new_totp_secret();admin.mfa_secret_encrypted=encrypt_secret(secret);db.commit();return {"secret":secret,"otpauth_uri":totp_uri(secret,admin.email)}\n@router.post("/mfa/verify")\ndef mfa_verify(token:str,code:str,db:Session=Depends(get_db)):\n try:p=decode_access_token(token)\n except Exception:raise HTTPException(401,"Invalid MFA challenge")\n if p.get("role")!="mfa":raise HTTPException(401,"Invalid MFA challenge")\n a=db.query(Admin).filter(Admin.id==p["sub"],Admin.enabled==True).first()\n if not a or not a.mfa_secret_encrypted or not verify_totp(decrypt_secret(a.mfa_secret_encrypted),code):raise HTTPException(401,"Invalid MFA code")\n return TokenOut(access_token=create_access_token(a.id,a.tenant_id,a.role.value),expires_in=settings.access_token_minutes*60)\n@router.post("/logout")
def logout():return {"status":"ok"}