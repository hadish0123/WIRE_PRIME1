from datetime import datetime,timedelta,timezone
import hashlib,secrets,jwt,pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from .config import settings
ph=PasswordHasher()
def hash_password(password):return ph.hash(password)
def verify_password(password,hashed):
 try:return ph.verify(hashed,password)
 except VerifyMismatchError:return False
def create_access_token(subject,tenant_id,role):
 exp=datetime.now(timezone.utc)+timedelta(minutes=settings.access_token_minutes)
 return jwt.encode({"sub":subject,"tenant_id":tenant_id,"role":role,"type":"access","exp":exp},settings.jwt_secret,algorithm=settings.jwt_algorithm)
def decode_access_token(token):
 p=jwt.decode(token,settings.jwt_secret,algorithms=[settings.jwt_algorithm],options={"require":["exp","sub","type"]})
 if p.get("type")!="access":raise jwt.InvalidTokenError("invalid access token")
 return p
def create_mfa_challenge(subject,tenant_id):
 exp=datetime.now(timezone.utc)+timedelta(minutes=5)
 return jwt.encode({"sub":subject,"tenant_id":tenant_id,"role":"mfa","type":"mfa_challenge","exp":exp},settings.jwt_secret,algorithm=settings.jwt_algorithm)
def decode_mfa_challenge(token):
 p=jwt.decode(token,settings.jwt_secret,algorithms=[settings.jwt_algorithm],options={"require":["exp","sub","type"]})
 if p.get("type")!="mfa_challenge" or p.get("role")!="mfa":raise jwt.InvalidTokenError("invalid MFA challenge")
 return p
def new_bootstrap_token():
 raw=secrets.token_urlsafe(32);return raw,hashlib.sha256(raw.encode()).hexdigest()
def hash_token(token):return hashlib.sha256(token.encode()).hexdigest()
def create_agent_token(node_id,tenant_id,scopes):
 if not settings.agent_signing_private_key:raise RuntimeError("Agent signing key is not configured")
 now=datetime.now(timezone.utc);exp=now+timedelta(minutes=settings.agent_access_minutes)
 return jwt.encode({"sub":node_id,"tenant_id":tenant_id,"type":"node_access","scopes":scopes,"iat":now,"exp":exp,"jti":secrets.token_hex(16),"iss":"primevpn-control","aud":"primevpn-agent"},settings.agent_signing_private_key,algorithm="EdDSA")
def _fernet():
 if not settings.data_encryption_key:raise RuntimeError("Data encryption key is not configured")
 return Fernet(settings.data_encryption_key.encode())
def encrypt_secret(value):return _fernet().encrypt(value.encode()).decode()
def decrypt_secret(value):return _fernet().decrypt(value.encode()).decode()
def new_totp_secret():return pyotp.random_base32()
def totp_uri(secret,email):return pyotp.TOTP(secret).provisioning_uri(name=email,issuer_name="PRIMEVPN")
def verify_totp(secret,code):return pyotp.TOTP(secret).verify(code,valid_window=1)
