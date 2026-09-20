import os
import jwt
from fastapi import HTTPException
VERIFY_KEY=os.environ.get("PRIMEVPN_AGENT_VERIFY_PUBLIC_KEY","")
def verify_control_token(token:str)->dict:
 if not VERIFY_KEY:raise HTTPException(503,"Agent verification key is not configured")
 try:return jwt.decode(token,VERIFY_KEY,algorithms=["EdDSA"],options={"require":["sub","exp","iat","jti","type"]},issuer="primevpn-control",audience="primevpn-agent")
 except jwt.PyJWTError as e:raise HTTPException(401,"Invalid agent credential") from e
def require_scope(claims:dict,scope:str):
 if claims.get("type")!="node_access" or scope not in claims.get("scopes",[]):raise HTTPException(403,"Agent scope denied")
