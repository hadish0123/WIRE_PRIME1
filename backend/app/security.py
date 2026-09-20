from datetime import datetime,timedelta,timezone
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from .config import settings
ph=PasswordHasher()
def hash_password(password): return ph.hash(password)
def verify_password(password,hashed):
 try:return ph.verify(hashed,password)
 except VerifyMismatchError:return False
def create_access_token(subject,tenant_id,role):
 exp=datetime.now(timezone.utc)+timedelta(minutes=settings.access_token_minutes)
 return jwt.encode({"sub":subject,"tenant_id":tenant_id,"role":role,"type":"access","exp":exp},settings.jwt_secret,algorithm=settings.jwt_algorithm)
def decode_access_token(token):
 return jwt.decode(token,settings.jwt_secret,algorithms=[settings.jwt_algorithm],options={"require":["exp","sub","type"]})