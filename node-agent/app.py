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
 if data.protocol=="openvpn" and shutil.which("openvpn"):
  fd,path=tempfile.mkstemp(prefix="primevpn-",suffix=".conf");os.close(fd)
  try:
   with open(path,"w",encoding="utf-8") as f:f.write(data.config)
   p=subprocess.run(["openvpn","--config",path,"--test-crypto"],capture_output=True,text=True,timeout=20)
   if p.returncode and "test-crypto" not in (p.stderr or ""):raise HTTPException(422,p.stderr.strip() or "OpenVPN configuration rejected")
  finally: 
   try:os.unlink(path)
   except FileNotFoundError:pass
 return {"valid":True,"protocol":data.protocol,"interface":data.interface}
@app.get("/health")
def health(x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"read")
 return {"status":"READY","version":VERSION,"capabilities":caps(),"time":datetime.now(timezone.utc).isoformat()}
@app.get("/capabilities")
def capabilities(x_agent_token:str|None=Header(default=None)):auth(x_agent_token,"read");return caps()
@app.post("/validate")
def validate(data:ApplyConfig,x_agent_token:str|None=Header(default=None)):auth(x_agent_token,"write");return validate_config(data)
@app.post("/apply")
def apply(data:ApplyConfig,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"write");validate_config(data)
 base="/etc/primevpn";os.makedirs(base,mode=0o700,exist_ok=True);name=safe_interface(data.interface);path=f"{base}/{name}.conf";tmp=path+".new";backup=path+".bak"
 if os.path.exists(path):shutil.copy2(path,backup)
 try:
  with open(tmp,"w",encoding="utf-8") as f:f.write(data.config)
  os.chmod(tmp,0o600);os.replace(tmp,path)
  for filename,body in data.files.items():
   if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}",filename): raise HTTPException(400,"Invalid artifact filename")
   artifact=f"{base}/{name}.{filename}"
   atmp=artifact+".new"
   with open(atmp,"w",encoding="utf-8") as f:f.write(body)
   os.chmod(atmp,0o600);os.replace(atmp,artifact)
  if data.protocol in {"wireguard","amneziawg"}:
   tool="wg-quick" if data.protocol=="wireguard" else "awg-quick"
   if not shutil.which(tool):raise RuntimeError(f"{tool} unavailable")
   subprocess.run([tool,"down",path],capture_output=True,text=True,timeout=20)
   subprocess.run([tool,"up",path],capture_output=True,text=True,timeout=20,check=True)
  elif data.protocol=="openvpn" and shutil.which("systemctl"):
   server_dir="/etc/openvpn/server";os.makedirs(server_dir,mode=0o700,exist_ok=True)
   server_conf=f"{server_dir}/{name}.conf"
   shutil.copy2(path,server_conf);os.chmod(server_conf,0o600)
   p=subprocess.run(["systemctl","reload-or-restart",f"openvpn-server@{name}"],capture_output=True,text=True,timeout=30)
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

class RevokePeer(BaseModel):
 interface:str=Field(min_length=1,max_length=80)
 public_key:str=Field(min_length=43,max_length=44)
@app.post("/peers/revoke")
def revoke_peer(data:RevokePeer,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"write");safe_interface(data.interface)
 if not shutil.which("wg"):raise HTTPException(503,"WireGuard unavailable")
 p=subprocess.run(["wg","set",data.interface,"peer",data.public_key,"remove"],capture_output=True,text=True,timeout=15)
 if p.returncode:raise HTTPException(502,p.stderr.strip() or "Peer revoke failed")
 return {"revoked":True,"interface":data.interface,"public_key":data.public_key}

class OpenVPNRevoke(BaseModel):
 instance:str=Field(min_length=1,max_length=80)
 crl_pem:str=Field(min_length=20,max_length=200000)
@app.post("/openvpn/crl")
def openvpn_crl(data:OpenVPNRevoke,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"write");safe_interface(data.instance)
 base="/etc/primevpn";os.makedirs(base,mode=0o700,exist_ok=True);path=f"{base}/{data.instance}.crl";tmp=path+".new"
 try:
  with open(tmp,"w",encoding="utf-8") as f:f.write(data.crl_pem)
  os.chmod(tmp,0o600);os.replace(tmp,path)
  if shutil.which("systemctl"):
   subprocess.run(["systemctl","reload-or-restart",f"openvpn-server@{data.instance}"],capture_output=True,text=True,timeout=30,check=True)
  return {"applied":True,"path":path}
 except Exception as e:
  try:os.unlink(tmp)
  except FileNotFoundError:pass
  raise HTTPException(502,f"CRL apply failed: {e}")

class RemoveConfig(BaseModel):
 protocol:str
 interface:str=Field(min_length=1,max_length=80)

@app.post("/remove")
def remove(data:RemoveConfig,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"write");name=safe_interface(data.interface);base="/etc/primevpn";path=f"{base}/{name}.conf"
 try:
  if data.protocol in {"wireguard","amneziawg"}:
   tool="wg-quick" if data.protocol=="wireguard" else "awg-quick"
   if shutil.which(tool): subprocess.run([tool,"down",path],capture_output=True,text=True,timeout=20)
  elif data.protocol=="openvpn" and shutil.which("systemctl"):
   subprocess.run(["systemctl","stop",f"openvpn-server@{name}"],capture_output=True,text=True,timeout=30)
  for p in [path,f"{path}.bak",f"{base}/{name}.ca.pem",f"{base}/{name}.server.pem",f"{base}/{name}.server.key",f"{base}/{name}.tls.key",f"{base}/{name}.crl.pem",f"{base}/{name}.new"]:
   try: os.unlink(p)
   except FileNotFoundError: pass
  try: os.unlink(f"/etc/openvpn/server/{name}.conf")
  except FileNotFoundError: pass
  return {"removed":True,"interface":name}
 except Exception as e:
  raise HTTPException(502,f"Remove failed: {e}")
