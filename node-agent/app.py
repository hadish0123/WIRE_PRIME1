import os,subprocess,shutil
from datetime import datetime,timezone
from fastapi import FastAPI,Header,HTTPException
from pydantic import BaseModel,Field
VERSION="100.0.0";TOKEN=os.environ.get("PRIMEVPN_AGENT_TOKEN","")
app=FastAPI(title="PRIMEVPN Node Agent",version=VERSION)
class ApplyConfig(BaseModel): protocol:str;interface:str=Field(min_length=1,max_length=80);config:str=Field(min_length=1,max_length=200000)
def auth(token):
 if not TOKEN or token!=TOKEN:raise HTTPException(401,"Agent authentication failed")
def caps():return {"wireguard":shutil.which("wg") is not None,"amneziawg":shutil.which("awg") is not None,"openvpn":shutil.which("openvpn") is not None}
@app.get("/health")
def health(x_agent_token:str|None=Header(default=None)):auth(x_agent_token);return {"status":"READY","version":VERSION,"capabilities":caps(),"time":datetime.now(timezone.utc).isoformat()}
@app.get("/capabilities")
def capabilities(x_agent_token:str|None=Header(default=None)):auth(x_agent_token);return caps()
@app.post("/validate")
def validate(data:ApplyConfig,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token)
 if data.protocol not in {"wireguard","amneziawg","openvpn"} or "\x00" in data.config:raise HTTPException(400,"Invalid configuration")
 return {"valid":True,"protocol":data.protocol,"interface":data.interface}
@app.post("/apply")
def apply(data:ApplyConfig,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token)
 if data.protocol not in {"wireguard","amneziawg","openvpn"} or "\x00" in data.config:raise HTTPException(400,"Invalid configuration")
 base="/etc/primevpn";os.makedirs(base,mode=0o700,exist_ok=True);path=f"{base}/{data.interface}.conf";tmp=path+".new"
 with open(tmp,"w",encoding="utf-8") as f:f.write(data.config)
 os.chmod(tmp,0o600);os.replace(tmp,path)
 if data.protocol in {"wireguard","amneziawg"}:
  tool="wg-quick" if data.protocol=="wireguard" else "awg-quick"
  if shutil.which(tool):
   subprocess.run([tool,"down",path],capture_output=True,text=True,timeout=20)
   subprocess.run([tool,"up",path],capture_output=True,text=True,timeout=20,check=True)
 elif shutil.which("systemctl"):
  subprocess.run(["systemctl","reload-or-restart",f"openvpn-server@{data.interface}"],capture_output=True,text=True,timeout=30,check=False)
 return {"applied":True,"protocol":data.protocol,"interface":data.interface}
@app.get("/counters/wireguard/{interface}")
def counters(interface:str,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token)
 if not shutil.which("wg"):raise HTTPException(503,"WireGuard unavailable")
 p=subprocess.run(["wg","show",interface,"dump"],capture_output=True,text=True,timeout=10)
 if p.returncode:raise HTTPException(503,p.stderr.strip() or "Unable to read counters")
 peers=[]
 for line in p.stdout.splitlines()[1:]:
  c=line.split("\t")
  if len(c)>=8:peers.append({"public_key":c[0],"endpoint":c[2],"last_handshake":int(c[4]),"bytes_received":int(c[5]),"bytes_sent":int(c[6])})
 return {"interface":interface,"peers":peers}