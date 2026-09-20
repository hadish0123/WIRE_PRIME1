import os,subprocess,shutil,re,tempfile
from datetime import datetime,timezone
from fastapi import FastAPI,Header,HTTPException
from pydantic import BaseModel,Field
from agent_security import verify_control_token,require_scope
VERSION="100.0.0"
TOKEN=os.environ.get("PRIMEVPN_AGENT_TOKEN","")
app=FastAPI(title="PRIMEVPN Node Agent",version=VERSION)
class ApplyConfig(BaseModel):
 protocol:str
 interface:str=Field(min_length=1,max_length=80)
 config:str=Field(min_length=1,max_length=200000)
def safe_interface(v):
 if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}",v):raise HTTPException(400,"Invalid interface")
 return v
def auth(token,scope="read"):
 if token and token.count(".")==2:
  claims=verify_control_token(token);require_scope(claims,scope);return
 if os.environ.get("PRIMEVPN_ALLOW_LEGACY_TOKEN","false").lower()=="true" and TOKEN and token==TOKEN:return
 raise HTTPException(401,"Agent authentication failed")
def caps():return {"wireguard":shutil.which("wg") is not None,"amneziawg":shutil.which("awg") is not None,"openvpn":shutil.which("openvpn") is not None}
def validate_config(data):
 safe_interface(data.interface)
 if data.protocol not in {"wireguard","amneziawg","openvpn"} or "\x00" in data.config:raise HTTPException(400,"Invalid configuration")
 if data.protocol=="openvpn" and shutil.which("openvpn"):
  fd,path=tempfile.mkstemp(prefix="primevpn-",suffix=".conf");os.close(fd)
  try:
   open(path,"w",encoding="utf-8").write(data.config)
   p=subprocess.run(["openvpn","--config",path,"--test-crypto"],capture_output=True,text=True,timeout=20)
   if p.returncode and "test-crypto" not in (p.stderr or ""):raise HTTPException(422,p.stderr.strip() or "OpenVPN configuration rejected")
  finally: 
   try:os.unlink(path)
   except FileNotFoundError:pass
 return {"valid":True,"protocol":data.protocol,"interface":data.interface}
@app.get("/health")
def health(x_agent_token:str|None=Header(default=None)):auth(x_agent_token,"read");return {"status":"READY","version":VERSION,"capabilities":caps(),"time":datetime.now(timezone.utc).isoformat()}
@app.get("/capabilities")
def capabilities(x_agent_token:str|None=Header(default=None)):auth(x_agent_token,"read");return caps()
@app.post("/validate")
def validate(data:ApplyConfig,x_agent_token:str|None=Header(default=None)):auth(x_agent_token,"write");return validate_config(data)
@app.post("/apply")
def apply(data:ApplyConfig,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"write");validate_config(data)
 base="/etc/primevpn";os.makedirs(base,mode=0o700,exist_ok=True);path=f"{base}/{safe_interface(data.interface)}.conf";tmp=path+".new";backup=path+".bak"
 if os.path.exists(path):shutil.copy2(path,backup)
 try:
  with open(tmp,"w",encoding="utf-8") as f:f.write(data.config)
  os.chmod(tmp,0o600);os.replace(tmp,path)
  if data.protocol in {"wireguard","amneziawg"}:
   tool="wg-quick" if data.protocol=="wireguard" else "awg-quick"
   if not shutil.which(tool):raise RuntimeError(f"{tool} unavailable")
   subprocess.run([tool,"down",path],capture_output=True,text=True,timeout=20)
   subprocess.run([tool,"up",path],capture_output=True,text=True,timeout=20,check=True)
  elif shutil.which("systemctl"):
   p=subprocess.run(["systemctl","reload-or-restart",f"openvpn-server@{data.interface}"],capture_output=True,text=True,timeout=30)
   if p.returncode:raise RuntimeError(p.stderr.strip() or "OpenVPN restart failed")
  return {"applied":True,"protocol":data.protocol,"interface":data.interface}
 except Exception as e:
  if os.path.exists(backup):shutil.copy2(backup,path)
  try:os.unlink(tmp)
  except FileNotFoundError:pass
  raise HTTPException(502,f"Apply failed and previous configuration was restored: {e}")
@app.get("/counters/wireguard/{interface}")
def counters(interface:str,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"read");safe_interface(interface)
 if not shutil.which("wg"):raise HTTPException(503,"WireGuard unavailable")
 p=subprocess.run(["wg","show",interface,"dump"],capture_output=True,text=True,timeout=10)
 if p.returncode:raise HTTPException(503,p.stderr.strip() or "Unable to read counters")
 peers=[]
 for line in p.stdout.splitlines()[1:]:
  c=line.split("\t")
  if len(c)>=8:peers.append({"public_key":c[0],"endpoint":c[2],"last_handshake":int(c[4]),"bytes_received":int(c[5]),"bytes_sent":int(c[6])})
 return {"interface":interface,"peers":peers}
def parse_openvpn_status(path):
 rows=[]
 if not os.path.isfile(path):raise HTTPException(503,"OpenVPN status unavailable")
 with open(path,"r",encoding="utf-8",errors="replace") as f:lines=f.read().splitlines()
 in_clients=False
 for line in lines:
  if line.startswith("Common Name,"):in_clients=True;continue
  if in_clients:
   if line=="ROUTING TABLE" or line.startswith("GLOBAL STATS"):break
   p=line.split(",")
   if len(p)>=5:
    try:rows.append({"common_name":p[0],"real_address":p[1],"bytes_received":int(p[2]),"bytes_sent":int(p[3]),"connected_since":p[4]})
    except ValueError:continue
 return rows
@app.get("/counters/openvpn/{instance}")
def openvpn_counters(instance:str,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"read");safe_interface(instance)
 return {"instance":instance,"clients":parse_openvpn_status(f"/run/primevpn/{instance}.status")}
