import os,subprocess,shutil,re,tempfile
from datetime import datetime,timezone
from fastapi import FastAPI,Header,HTTPException
from pydantic import BaseModel,Field
from agent_security import verify_control_token,require_scope
VERSION="100.0.5" # full infrastructure preflight and WireGuard diagnostics

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
@app.get("/healthz")
def healthz():
 return {"status":"ok","version":VERSION}

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
 auth(x_agent_token,"write");safe_interface(data.interface)
 base="/etc/primevpn";name=safe_interface(data.interface);path=f"{base}/{name}.conf";tmp=path+".new";backup=path+".bak"
 previous_files={}
 try:
  os.makedirs(base,mode=0o700,exist_ok=True)
  if os.path.exists(path):shutil.copy2(path,backup)
  for filename,body in data.files.items():
   if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}",filename):raise HTTPException(400,"Invalid artifact filename")
   artifact=f"{base}/{name}.{filename}";previous_files[artifact]=open(artifact,"rb").read() if os.path.exists(artifact) else None
   atmp=artifact+".new"
   with open(atmp,"w",encoding="utf-8") as f:f.write(body)
   os.chmod(atmp,0o600);os.replace(atmp,artifact)
  with open(tmp,"w",encoding="utf-8") as f:f.write(data.config)
  os.chmod(tmp,0o600);os.replace(tmp,path)
  validate_config(data)
  if data.protocol in {"wireguard","amneziawg"}:
   tool="wg-quick" if data.protocol=="wireguard" else "awg-quick"
   if not shutil.which(tool):raise RuntimeError(f"{tool} unavailable")
   if data.protocol=="wireguard" and shutil.which("wg") and shutil.which("wg-quick") and os.path.exists(f"/sys/class/net/{name}"):
    try:
     stripped=subprocess.run(["wg-quick","strip",path],capture_output=True,text=True,timeout=20,check=True)
     subprocess.run(["wg","syncconf",name,"/dev/stdin"],input=stripped.stdout,capture_output=True,text=True,timeout=20,check=True)
    except subprocess.CalledProcessError as e:
     detail=e.stderr.strip() or e.stdout.strip() or str(e)
     down=subprocess.run([tool,"down",path],capture_output=True,text=True,timeout=20)
     try:
      subprocess.run([tool,"up",path],capture_output=True,text=True,timeout=20,check=True)
     except subprocess.CalledProcessError as up_error:
      up_detail=up_error.stderr.strip() or up_error.stdout.strip() or str(up_error)
      raise RuntimeError(f"WireGuard syncconf failed: {detail}; wg-quick up failed: {up_detail}") from up_error
   else:
    if os.path.exists(f"/sys/class/net/{name}"):
     subprocess.run([tool,"down",path],capture_output=True,text=True,timeout=20)
    subprocess.run([tool,"up",path],capture_output=True,text=True,timeout=20,check=True)
   if data.protocol=="wireguard":
    if shutil.which("sysctl"): subprocess.run(["sysctl","-w","net.ipv4.ip_forward=1"],capture_output=True,text=True,timeout=10,check=True)
    port_match=re.search(r"(?m)^ListenPort\s*=\s*(\d+)",data.config)
    if not port_match: raise RuntimeError("WireGuard ListenPort is missing")
    listen_port=int(port_match.group(1))
    if shutil.which("iptables"):
     check=subprocess.run(["iptables","-C","INPUT","-p","udp","--dport",str(listen_port),"-j","ACCEPT"],capture_output=True,text=True,timeout=10)
     if check.returncode:
      subprocess.run(["iptables","-I","INPUT","-p","udp","--dport",str(listen_port),"-j","ACCEPT"],capture_output=True,text=True,timeout=10,check=True)
    if shutil.which("ip6tables"):
     check=subprocess.run(["ip6tables","-C","INPUT","-p","udp","--dport",str(listen_port),"-j","ACCEPT"],capture_output=True,text=True,timeout=10)
     if check.returncode:
      subprocess.run(["ip6tables","-I","INPUT","-p","udp","--dport",str(listen_port),"-j","ACCEPT"],capture_output=True,text=True,timeout=10,check=True)
    if shutil.which("netfilter-persistent"):
     subprocess.run(["netfilter-persistent","save"],capture_output=True,text=True,timeout=15)
    live=subprocess.run(["wg","show",name,"listen-port"],capture_output=True,text=True,timeout=10,check=True).stdout.strip()
    if live != str(listen_port): raise RuntimeError(f"WireGuard listener mismatch: configured={listen_port} live={live}")
    if shutil.which("iptables"):
     out=subprocess.run(["ip","route","show","default"],capture_output=True,text=True,timeout=10,check=True).stdout.split()
     if out:
      wan=out[out.index("dev")+1] if "dev" in out else ""
      if wan:
       import re as _re
       m=_re.search(r"(?m)^Address\s*=\s*([^\n]+)",data.config)
       cidr=m.group(1).strip() if m else ""
       if "/" in cidr:
        net=__import__("ipaddress").ip_interface(cidr).network
        rules=[
         ["iptables","-C","FORWARD","-i",name,"-j","ACCEPT"],
         ["iptables","-C","FORWARD","-o",name,"-m","conntrack","--ctstate","RELATED,ESTABLISHED","-j","ACCEPT"],
        ]
        for rule in rules:
         check=subprocess.run(rule,capture_output=True,text=True,timeout=10)
         if check.returncode:
          subprocess.run([rule[0],"-A"]+rule[2:],capture_output=True,text=True,timeout=10,check=True)
        check=subprocess.run(["iptables","-t","nat","-C","POSTROUTING","-s",str(net),"-o",wan,"-j","MASQUERADE"],capture_output=True,text=True,timeout=10)
        if check.returncode:
         subprocess.run(["iptables","-t","nat","-A","POSTROUTING","-s",str(net),"-o",wan,"-j","MASQUERADE"],capture_output=True,text=True,timeout=10,check=True)
        port_match=re.search(r"(?m)^ListenPort\s*=\s*(\d+)",data.config)
        if port_match:
         listen_port=port_match.group(1)
         if shutil.which("ufw") and "active" in subprocess.run(["ufw","status"],capture_output=True,text=True,timeout=10).stdout.lower():
          subprocess.run(["ufw","allow",f"{listen_port}/udp"],capture_output=True,text=True,timeout=10,check=True)
         if shutil.which("firewall-cmd") and subprocess.run(["firewall-cmd","--state"],capture_output=True,text=True,timeout=10).returncode==0:
          subprocess.run(["firewall-cmd","--permanent","--add-port",f"{listen_port}/udp"],capture_output=True,text=True,timeout=10,check=True)
          subprocess.run(["firewall-cmd","--reload"],capture_output=True,text=True,timeout=10,check=True)
  elif data.protocol=="openvpn":
   if not shutil.which("systemctl"):raise RuntimeError("systemctl unavailable")
   server_dir="/etc/openvpn/server";os.makedirs(server_dir,mode=0o700,exist_ok=True)
   server_conf=f"{server_dir}/{name}.conf";shutil.copy2(path,server_conf);os.chmod(server_conf,0o600)
   p=subprocess.run(["systemctl","reload-or-restart",f"openvpn-server@{name}"],capture_output=True,text=True,timeout=30)
   if p.returncode:raise RuntimeError(p.stderr.strip() or "OpenVPN restart failed")
  return {"applied":True,"protocol":data.protocol,"interface":data.interface}
 except HTTPException: raise
 except Exception as e:
  if os.path.exists(backup):shutil.copy2(backup,path)
  else:
   try:os.unlink(path)
   except FileNotFoundError:pass
  for artifact,old in previous_files.items():
   if old is None:
    try:os.unlink(artifact)
    except FileNotFoundError:pass
   else:
    with open(artifact,"wb") as f:f.write(old)
  try:os.unlink(tmp)
  except FileNotFoundError:pass
  raise HTTPException(502,f"Apply failed and previous configuration was restored: {e}")


def _cmd(args, timeout=10):
 try:
  p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
  return p.returncode,p.stdout.strip(),p.stderr.strip()
 except Exception as e:
  return 99,"",str(e)

@app.get("/diagnostics/preflight")
def preflight(x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"read")
 checks=[];issues=[];obs={}
 def check(name,ok,detail,critical=True):
  item={"name":name,"ok":bool(ok),"detail":detail,"critical":bool(critical)}
  checks.append(item)
  if critical and not ok: issues.append(item)
 rc,out,err=_cmd(["systemctl","is-system-running"],5)
 check("systemd",rc==0 or out in {"degraded","running"},out or err,True)
 rc,out,err=_cmd(["python3","--version"],5);check("python3",rc==0,out or err,True)
 rc,out,err=_cmd(["openssl","version"],5);check("openssl",rc==0,out or err,True)
 rc,out,err=_cmd(["ip","route","show","default"],5)
 check("default route",rc==0 and bool(out),out or err,True)
 wan=""
 if out:
  parts=out.split()
  if "dev" in parts: wan=parts[parts.index("dev")+1]
 obs["default_route"]=out;obs["wan_interface"]=wan
 rc,out,err=_cmd(["ip","-4","addr","show","scope","global"],5)
 pub=""
 for line in out.splitlines():
  m=re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/",line)
  if m and not m.group(1).startswith(("10.","192.168.","172.16.")): pub=m.group(1);break
 rc2,src,err2=_cmd(["ip","route","get","1.1.1.1"],5)
 m=re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)",src)
 egress=m.group(1) if m else ""
 obs["public_ipv4"]=pub;obs["egress_source"]=egress
 check("egress source",bool(egress),egress or err2,True)
 rc,out,err=_cmd(["getent","hosts","api.ipify.org"],5);check("DNS resolution",rc==0 and bool(out),out or err,True)
 rc,out,err=_cmd(["curl","-4","-fsS","--max-time","10","https://api.ipify.org"],15);check("HTTPS egress",rc==0 and bool(out),out or err,True)
 rc,out,err=_cmd(["sysctl","-n","net.ipv4.ip_forward"],5);check("IPv4 forwarding",rc==0 and out=="1",out or err,True)
 rc,out,err=_cmd(["sysctl","-n","net.ipv4.conf.all.rp_filter"],5);check("rp_filter",rc==0 and out in {"0","2"},out or err,False)
 check("wg installed",bool(shutil.which("wg")),"wg" if shutil.which("wg") else "missing",True)
 check("wg-quick installed",bool(shutil.which("wg-quick")),"wg-quick" if shutil.which("wg-quick") else "missing",True)
 rc,out,err=_cmd(["modprobe","-n","wireguard"],5) if shutil.which("modprobe") else (1,"","modprobe missing")
 check("WireGuard kernel support",rc==0,out or err,False)
 fw=shutil.which("iptables") or shutil.which("nft")
 check("firewall tool",bool(fw),fw or "iptables/nft missing",True)
 rc,out,err=_cmd(["systemctl","is-active","primevpn-node-agent.service"],5)
 check("Node Agent service",rc==0 and out=="active",out or err,True)
 rc,out,err=_cmd(["ss","-ltnH"],5)
 agent_port=bool(out)
 check("TCP listeners available",rc==0, "listeners detected" if agent_port else "no listeners",False)
 wg_if=[]
 rc,out,err=_cmd(["wg","show","interfaces"],5)
 if rc==0: wg_if=out.split()
 obs["wireguard_interfaces"]=wg_if;obs["agent_service"]=out
 check("runtime WireGuard interfaces",True,",".join(wg_if) if wg_if else "none yet; allowed before first config",False)
 obs["client_traffic_verified"]=False
 obs["traffic_reason"]="No client/inbound runtime traffic was supplied; handshake and forwarding cannot be claimed yet."
 ready=not issues
 return {"ready":ready,"checks":checks,"issues":issues,"observed":obs,
         "traffic":{"client_traffic_verified":False,"reason":obs["traffic_reason"]},
         "summary":"NODE READY: infrastructure baseline passed" if ready else "NODE PREFLIGHT FAILED"}

@app.get("/diagnostics/wireguard/{interface}/{port}")
def wireguard_diagnostics(interface:str,port:int,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"read");safe_interface(interface)
 if port<1 or port>65535: raise HTTPException(400,"Invalid UDP port")
 listener=subprocess.run(["wg","show",interface,"listen-port"],capture_output=True,text=True,timeout=10) if shutil.which("wg") else None
 iptables_rules=[]
 if shutil.which("iptables"):
  p=subprocess.run(["iptables","-L","INPUT","-v","-n","-x"],capture_output=True,text=True,timeout=10)
  for line in p.stdout.splitlines():
   if "udp" in line and f"dpt:{port}" in line: iptables_rules.append(line.strip())
 nft_lines=[]
 if shutil.which("nft"):
  p=subprocess.run(["nft","-a","list","ruleset"],capture_output=True,text=True,timeout=10)
  for line in p.stdout.splitlines():
   if "udp" in line and str(port) in line: nft_lines.append(line.strip())
 route=subprocess.run(["ip","route","show","default"],capture_output=True,text=True,timeout=10) if shutil.which("ip") else None
 peer_count=0\n peer_details=[]\n if shutil.which("wg") and listener and listener.returncode==0:\n  dump=subprocess.run(["wg","show",interface,"dump"],capture_output=True,text=True,timeout=10)\n  if dump.returncode==0:\n   for line in dump.stdout.splitlines()[1:]:\n    c=line.split("\\t")\n    if len(c)>=8 and c[0]:\n     peer_count+=1\n     peer_details.append({"public_key":c[0],"endpoint":c[2],"last_handshake":int(c[4]),"bytes_received":int(c[5]),"bytes_sent":int(c[6])})\n return {"interface":interface,"configured_port":port,"live_port":(listener.stdout.strip() if listener and listener.returncode==0 else None),"peer_count":peer_count,"peers":peer_details,"iptables_input_matches":iptables_rules,"nft_udp_port_matches":nft_lines[:20],"default_route":(route.stdout.strip() if route and route.returncode==0 else None)}
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
 base="/etc/primevpn";os.makedirs(base,mode=0o700,exist_ok=True);path=f"{base}/{data.instance}.crl.pem";tmp=path+".new"
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
