import os,subprocess,shutil,re,tempfile
from datetime import datetime,timezone
from fastapi import FastAPI,Header,HTTPException
from pydantic import BaseModel,Field
from agent_security import verify_control_token,require_scope
VERSION="100.0.0"
app=FastAPI(title="PRIMEVPN Node Agent",version=VERSION)
class ApplyConfig(BaseModel):
 protocol:str
 interface:str=Field(min_length=1,max_length=80)
 config:str=Field(min_length=1,max_length=200000)
 files:dict[str,str]=Field(default_factory=dict)
def safe_interface(v):
 if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}",v):raise HTTPException(400,"Invalid interface")
 return v
def auth(token,scope="read"):
 if token and token.count(".")==2:
  claims=verify_control_token(token);require_scope(claims,scope);return
 raise HTTPException(401,"Agent authentication failed")
def caps():return {"wireguard":shutil.which("wg") is not None,"amneziawg":shutil.which("awg") is not None,"openvpn":shutil.which("openvpn") is not None}
def validate_config(data):
 safe_interface(data.interface)
 if data.protocol not in {"wireguard","amneziawg","openvpn"} or "\x00" in data.config:raise HTTPException(400,"Invalid configuration")
 return {"valid":True,"protocol":data.protocol,"interface":data.interface}
@app.get("/healthz")
def healthz(): return {"status":"ok","version":VERSION}
@app.get("/health")
def health(x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"read");return {"status":"READY","version":VERSION,"capabilities":caps(),"time":datetime.now(timezone.utc).isoformat()}
@app.get("/capabilities")
def capabilities(x_agent_token:str|None=Header(default=None)):auth(x_agent_token,"read");return caps()
@app.post("/validate")
def validate(data:ApplyConfig,x_agent_token:str|None=Header(default=None)):auth(x_agent_token,"write");return validate_config(data)
