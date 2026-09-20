import os
import jwt
from fastapi import HTTPException
VERIFY_KEY=os.environ.get("PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY","")
NODE_ID=os.environ.get("PRIMEVPN_NODE_ID","")
def verify_control_token(token:str)->dict:
 if not VERIFY_KEY or not NODE_ID:raise HTTPException(503,"Agent identity is not configured")
 try:
  claims=jwt.decode(token,VERIFY_KEY,algorithms=["EdDSA"],options={"require":["sub","exp","iat","jti","type"]},issuer="primevpn-control",audience="primevpn-agent")
 except jwt.PyJWTError as e:
  raise HTTPException(401,"Invalid agent credential") from e
 if claims.get("type")!="node_access" or claims.get("sub")!=NODE_ID:raise HTTPException(403,"Agent identity mismatch")
 return claims
def require_scope(claims:dict,scope:str):
 if scope not in claims.get("scopes",[]):raise HTTPException(403,"Agent scope denied")
