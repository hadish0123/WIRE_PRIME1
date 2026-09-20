import os,time,jwt
from fastapi import HTTPException
from cryptography.hazmat.primitives import serialization
PRIVATE_KEY=os.environ.get("PRIMEVPN_AGENT_SIGNING_PRIVATE_KEY","")
def verify_control_token(token:str)->dict:
 if not PRIVATE_KEY: raise HTTPException(503,"Agent signing key is not configured")
 try:
  return jwt.decode(token,PRIVATE_KEY,algorithms=["EdDSA"],options={"require":["sub","exp","iat","jti","type"]},issuer="primevpn-control",audience="primevpn-agent")
 except jwt.PyJWTError as e: raise HTTPException(401,"Invalid agent credential") from e
def require_scope(claims:dict,scope:str):
 if scope not in claims.get("scopes",[]):raise HTTPException(403,"Agent scope denied")
 if claims.get("type")!="node_access":raise HTTPException(401,"Invalid credential type")
