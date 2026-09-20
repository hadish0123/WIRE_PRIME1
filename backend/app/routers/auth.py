from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from ..db import get_db
from ..schemas import LoginIn,TokenOut,MeOut
from ..models import Admin
from ..security import verify_password,create_access_token
from ..deps import current_admin
from ..config import settings
router=APIRouter()
@router.post("/login",response_model=TokenOut)
def login(data:LoginIn,db:Session=Depends(get_db)):
 a=db.query(Admin).filter(Admin.email==data.email.lower()).first()
 if not a or not verify_password(data.password,a.password_hash):raise HTTPException(401,"Invalid credentials")
 return TokenOut(access_token=create_access_token(a.id,a.tenant_id,a.role.value),expires_in=settings.access_token_minutes*60)
@router.get("/me",response_model=MeOut)
def me(admin:Admin=Depends(current_admin)):return admin
@router.post("/logout")
def logout():return {"status":"ok"}