import os
import jwt
from fastapi import HTTPException
VERIFY_KEY=os.environ.get("PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY","")
VERIFY_FILE=os.environ.get("PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY_FILE","")
NODE_ID=os.environ.get("PRIMEVPN_NODE_ID","")
def _key():
 if VERIFY_FILE:
  try:return open(VERIFY_FILE,"r",encoding="utf-8").read()
  except OSError:pass
 return VERIFY_KEY
def verify_control_token(token:str)->dict:
 key=_key()
 if not key or not NODE_ID:raise HTTPException(503,"Agent identity is not configured")
 try:claims=jwt.decode(token,key,algorithms=["EdDSA"],options={"require":["sub","exp","iat","jti","type"]},issuer="primevpn-control",audience="primevpn-agent")
 except jwt.PyJWTError as e:raise HTTPException(401,"Invalid agent credential") from e
 if claims.get("type")!="node_access" or claims.get("sub")!=NODE_ID:raise HTTPException(403,"Agent identity mismatch")
 return claims
def require_scope(claims:dict,scope:str):
 if scope not in claims.get("scopes",[]):raise HTTPException(403,"Agent scope denied")
