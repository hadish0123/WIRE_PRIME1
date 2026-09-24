import os,subprocess,shutil,re,tempfile
from datetime import datetime,timezone
from fastapi import FastAPI,Header,HTTPException
from pydantic import BaseModel,Field
from agent_security import verify_control_token,require_scope
VERSION="100.1.0" # full WireGuard + AmneziaWG runtime support

app=FastAPI(title="PRIMEVPN Node Agent",version=VERSION)
class WireGuardSmoke(BaseModel):
 client_private_key:str=Field(min_length=40,max_length=100)
 client_address:str=Field(min_length=7,max_length=64)
 server_public_key:str=Field(min_length=40,max_length=100)
 endpoint:str=Field(min_length=3,max_length=255)

class ApplyConfig(BaseModel):
 protocol:str
 interface:str=Field(min_length=1,max_length=80)
 config:str=Field(min_length=1,max_length=200000)
 files:dict[str,str]=Field(default_factory=dict)
def safe_interface(v):
 if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}",v):raise HTTPException(400,"Invalid interface")
 return v
def prepare_wireguard_interface(name):
 # Prevent broad cloud-init/networkd rules from removing wg-quick addresses.
 directory="/etc/systemd/network"
 os.makedirs(directory,exist_ok=True)
 with open(f"{directory}/00-primevpn-{name}.network","w",encoding="utf-8") as f:
  f.write(f"[Match]\nName={name}\n[Link]\nUnmanaged=yes\n")
 if shutil.which("networkctl") and shutil.which("systemctl"):
  state=subprocess.run(["systemctl","is-active","systemd-networkd"],capture_output=True,text=True,timeout=10)
  if state.returncode==0:
   subprocess.run(["networkctl","reload"],capture_output=True,text=True,timeout=10,check=True)
   if os.path.exists(f"/sys/class/net/{name}"):
    subprocess.run(["networkctl","reconfigure",name],capture_output=True,text=True,timeout=10)


def persist_wireguard_interface(name,tool,path):
 if not shutil.which("systemctl"):return
 unit=f"primevpn-wireguard-{name}.service"
 executable=shutil.which(tool)
 content=("[Unit]\nDescription=PRIMEVPN WireGuard interface\n"
          "After=network-online.target netfilter-persistent.service\nWants=network-online.target\n"
          f"[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart={executable} up {path}\n"
          f"ExecStop={executable} down {path}\n[Install]\nWantedBy=multi-user.target\n")
 with open(f"/etc/systemd/system/{unit}","w",encoding="utf-8") as f:f.write(content)
 subprocess.run(["systemctl","daemon-reload"],capture_output=True,text=True,timeout=10,check=True)
 subprocess.run(["systemctl","enable",unit],capture_output=True,text=True,timeout=10,check=True)


def without_peer(config,public_key):
 blocks=re.split(r"(?m)^\[Peer\]\s*\n",config)
 kept=[]
 for block in blocks[1:]:
  match=re.search(r"(?m)^PublicKey\s*=\s*(\S+)\s*$",block)
  if not match or match.group(1)!=public_key:kept.append(block)
 return blocks[0]+"".join("[Peer]\n"+block for block in kept)

def auth(token,scope="read"):
 if token and token.count(".")==2:
  claims=verify_control_token(token);require_scope(claims,scope);return

 raise HTTPException(401,"Agent authentication failed")
def _run_checked(cmd,timeout=180,env=None):
 p=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,env=env)
 if p.returncode:
  raise RuntimeError((p.stderr or p.stdout or "command failed").strip())
 return p

def ensure_amneziawg():
 if shutil.which("awg") and shutil.which("awg-quick"):
  if shutil.which("modprobe"):
   subprocess.run(["modprobe","amneziawg"],capture_output=True,text=True,timeout=30)
  return
 if not shutil.which("apt-get"):
  raise RuntimeError("AmneziaWG is not installed and automatic installation is currently supported on Debian/Ubuntu nodes only")
 env=os.environ.copy();env["DEBIAN_FRONTEND"]="noninteractive"
 kernel=subprocess.run(["uname","-r"],capture_output=True,text=True,timeout=10,check=True).stdout.strip()
 _run_checked(["apt-get","update","-y"],180,env)
 _run_checked(["apt-get","install","-y","software-properties-common","python3-launchpadlib","gnupg2","dkms","build-essential",f"linux-headers-{kernel}"],300,env)
 if not shutil.which("add-apt-repository"):
  raise RuntimeError("add-apt-repository is unavailable after installing software-properties-common")
 p=subprocess.run(["add-apt-repository","-y","ppa:amnezia/ppa"],capture_output=True,text=True,timeout=120,env=env)
 if p.returncode and "already exists" not in ((p.stderr or "")+(p.stdout or "")).lower():
  raise RuntimeError((p.stderr or p.stdout or "failed to add Amnezia PPA").strip())
 _run_checked(["apt-get","update","-y"],180,env)
 _run_checked(["apt-get","install","-y","amneziawg"],300,env)
 if shutil.which("modprobe"):
  _run_checked(["modprobe","amneziawg"],60,env)
 if not shutil.which("awg") or not shutil.which("awg-quick"):
  raise RuntimeError("AmneziaWG package installed but awg/awg-quick are unavailable")

def caps():return {"wireguard":shutil.which("wg") is not None,"amneziawg":shutil.which("awg") is not None and shutil.which("awg-quick") is not None,"openvpn":shutil.which("openvpn") is not None}
def allow_input_port(port,protocol):
 if not port or not str(port).isdigit(): return
 port=str(port)
 if shutil.which("iptables"):
  proto="udp" if protocol in {"wireguard","amneziawg"} else "tcp"
  check=subprocess.run(["iptables","-C","INPUT","-p",proto,"--dport",port,"-j","ACCEPT"],capture_output=True,text=True,timeout=10)
  if check.returncode:
   subprocess.run(["iptables","-I","INPUT","-p",proto,"--dport",port,"-j","ACCEPT"],capture_output=True,text=True,timeout=10,check=True)
 proto="udp" if protocol in {"wireguard","amneziawg"} else "tcp"
 if shutil.which("ufw"):
  status=subprocess.run(["ufw","status"],capture_output=True,text=True,timeout=10)
  if "Status: active" in status.stdout and f"{port}/{proto}" not in status.stdout:
   subprocess.run(["ufw","allow",f"{port}/{proto}"],capture_output=True,text=True,timeout=10,check=True)
 if shutil.which("firewall-cmd"):
  state=subprocess.run(["firewall-cmd","--state"],capture_output=True,text=True,timeout=10)
  if state.returncode==0:
   query=subprocess.run(["firewall-cmd","--permanent","--query-port",f"{port}/{proto}"],capture_output=True,text=True,timeout=10)
   if query.returncode!=0:
    subprocess.run(["firewall-cmd","--permanent","--add-port",f"{port}/{proto}"],capture_output=True,text=True,timeout=10,check=True)
    subprocess.run(["firewall-cmd","--reload"],capture_output=True,text=True,timeout=10,check=True)
 if shutil.which("netfilter-persistent"):
  subprocess.run(["netfilter-persistent","save"],capture_output=True,text=True,timeout=20)
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
   if data.protocol=="amneziawg": ensure_amneziawg()
   tool="wg-quick" if data.protocol=="wireguard" else "awg-quick"
   prepare_wireguard_interface(name)
   if not shutil.which(tool):raise RuntimeError(f"{tool} unavailable")
   if data.protocol=="wireguard" and shutil.which("wg") and shutil.which("wg-quick") and os.path.exists(f"/sys/class/net/{name}"):
    # wg syncconf updates WireGuard keys/peers but not interface IP addresses,
    # routes or MTU. Reusing a VPS with an old PRIMEVPN wg0 can therefore leave
    # a perfectly valid handshake on the wrong tunnel subnet and break ping/data.
    addr_match=re.search(r"(?m)^Address\s*=\s*([^\n]+)",data.config)
    expected_addr=(addr_match.group(1).split(",")[0].strip() if addr_match else "")
    addr_state=subprocess.run(["ip","-o","addr","show","dev",name],capture_output=True,text=True,timeout=10)
    address_ok=bool(expected_addr) and expected_addr in addr_state.stdout
    mtu_match=re.search(r"(?m)^MTU\s*=\s*(\d+)\s*$",data.config)
    mtu_ok=True
    if mtu_match:
     link_state=subprocess.run(["ip","-o","link","show","dev",name],capture_output=True,text=True,timeout=10)
     mtu_ok=bool(re.search(r"\bmtu\s+"+re.escape(mtu_match.group(1))+r"\b",link_state.stdout))
    if not address_ok or not mtu_ok:
     subprocess.run([tool,"down",path],capture_output=True,text=True,timeout=20)
     subprocess.run(["ip","link","del",name],capture_output=True,text=True,timeout=10)
     subprocess.run([tool,"up",path],capture_output=True,text=True,timeout=20,check=True)
    else:
     try:
      stripped=subprocess.run(["wg-quick","strip",path],capture_output=True,text=True,timeout=20,check=True)
      subprocess.run(["wg","syncconf",name,"/dev/stdin"],input=stripped.stdout,capture_output=True,text=True,timeout=20,check=True)
     except subprocess.CalledProcessError as e:
      detail=e.stderr.strip() or e.stdout.strip() or str(e)
      subprocess.run([tool,"down",path],capture_output=True,text=True,timeout=20)
      subprocess.run(["ip","link","del",name],capture_output=True,text=True,timeout=10)
      try:
       subprocess.run([tool,"up",path],capture_output=True,text=True,timeout=20,check=True)
      except subprocess.CalledProcessError as up_error:
       up_detail=up_error.stderr.strip() or up_error.stdout.strip() or str(up_error)
       raise RuntimeError(f"WireGuard syncconf failed: {detail}; wg-quick up failed: {up_detail}") from up_error
   else:
    if os.path.exists(f"/sys/class/net/{name}"):
     subprocess.run([tool,"down",path],capture_output=True,text=True,timeout=20)
    subprocess.run([tool,"up",path],capture_output=True,text=True,timeout=20,check=True)
   if data.protocol in {"wireguard","amneziawg"}:
    if shutil.which("sysctl"): subprocess.run(["sysctl","-w","net.ipv4.ip_forward=1"],capture_output=True,text=True,timeout=10,check=True)
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
        # Open/reload the host firewall first. UFW/firewalld reloads may rewrite
        # their backend chains, so PRIMEVPN forwarding/NAT rules must be installed
        # afterwards, not before.
        port_match=re.search(r"(?m)^ListenPort\s*=\s*(\d+)",data.config)
        if port_match:
         allow_input_port(port_match.group(1),"wireguard")
        tunnel_ping=["iptables","-C","INPUT","-i",name,"-p","icmp","--icmp-type","echo-request","-j","ACCEPT"]
        if subprocess.run(tunnel_ping,capture_output=True,text=True,timeout=10).returncode:
         subprocess.run(["iptables","-I","INPUT","1","-i",name,"-p","icmp","--icmp-type","echo-request","-j","ACCEPT"],capture_output=True,text=True,timeout=10,check=True)
        rules=[
         ["iptables","-C","FORWARD","-i",name,"-j","ACCEPT"],
         ["iptables","-C","FORWARD","-o",name,"-m","conntrack","--ctstate","RELATED,ESTABLISHED","-j","ACCEPT"],
        ]
        for rule in rules:
         check=subprocess.run(rule,capture_output=True,text=True,timeout=10)
         if check.returncode:
          subprocess.run([rule[0],"-I",rule[2],"1"]+rule[3:],capture_output=True,text=True,timeout=10,check=True)
        check=subprocess.run(["iptables","-t","nat","-C","POSTROUTING","-s",str(net),"-o",wan,"-j","MASQUERADE"],capture_output=True,text=True,timeout=10)
        if check.returncode:
         subprocess.run(["iptables","-t","nat","-I","POSTROUTING","1","-s",str(net),"-o",wan,"-j","MASQUERADE"],capture_output=True,text=True,timeout=10,check=True)
        # Persist forwarding/NAT after the inbound is created. The installer runs
        # before an inbound exists, so saving only during installation loses these
        # rules after a VPS reboot.
        if shutil.which("netfilter-persistent"):
         subprocess.run(["netfilter-persistent","save"],capture_output=True,text=True,timeout=20)
        elif os.path.isdir("/etc/sysconfig") and shutil.which("iptables-save"):
         with open("/etc/sysconfig/iptables","w",encoding="utf-8") as f:
          subprocess.run(["iptables-save"],stdout=f,text=True,timeout=20,check=True)
   persist_wireguard_interface(name,tool,path)
  elif data.protocol=="openvpn":
   if not shutil.which("systemctl"):raise RuntimeError("systemctl unavailable")
   server_dir="/etc/openvpn/server";os.makedirs(server_dir,mode=0o700,exist_ok=True)
   server_conf=f"{server_dir}/{name}.conf";shutil.copy2(path,server_conf);os.chmod(server_conf,0o600)
   proto_match=re.search(r"(?m)^proto\\s+(udp|tcp)(?:-server)?\\s*$",data.config)
   port_match=re.search(r"(?m)^port\\s+(\\d+)\\s*$",data.config)
   if port_match:
    allow_input_port(port_match.group(1),"openvpn")
   subprocess.run(["systemctl","daemon-reload"],capture_output=True,text=True,timeout=10)
   p=subprocess.run(["systemctl","enable",f"openvpn-server@{name}"],capture_output=True,text=True,timeout=20)
   if p.returncode:raise RuntimeError(p.stderr.strip() or "OpenVPN enable failed")
   p=subprocess.run(["systemctl","restart",f"openvpn-server@{name}"],capture_output=True,text=True,timeout=30)
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

def _wg_dump(interface,protocol="wireguard"):
 tool="awg" if protocol=="amneziawg" else "wg"
 if not shutil.which(tool): raise RuntimeError(f"{tool} unavailable")
 p=subprocess.run([tool,"show",interface,"dump"],capture_output=True,text=True,timeout=10)
 if p.returncode!=0: raise RuntimeError(p.stderr.strip() or "wg dump failed")
 rows=p.stdout.splitlines()
 if not rows: raise RuntimeError("empty wg dump")
 head=rows[0].split("\t")
 peers=[]
 for line in rows[1:]:
  parts=line.split("\t")
  if len(parts)>=8:
   peers.append({"public_key":parts[0],"preshared_key_configured":parts[1] != "0000000000000000000000000000000000000000000000000000000000000000","endpoint":parts[2],"allowed_ips":parts[3],"last_handshake":int(parts[4]),"bytes_received":int(parts[5]),"bytes_sent":int(parts[6]),"persistent_keepalive":0 if parts[7] == "off" else int(parts[7])})
 return {"public_key":head[1],"private_key_present":head[0] != "(none)","listen_port":int(head[2]),"fwmark":head[3],"peers":peers}

@app.post("/diagnostics/wireguard-smoke")
def wireguard_smoke(data:WireGuardSmoke,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"write")
 if not shutil.which("wg") or not shutil.which("ip"): raise HTTPException(503,"WireGuard/ip tools unavailable")
 import ipaddress,time
 try:
  addr=ipaddress.ip_interface(data.client_address)
  if addr.version!=4: raise ValueError("Smoke test currently requires IPv4")
  private_path=tempfile.mktemp(prefix="primevpn-smoke-key-")
  try:
   with open(private_path,"w",encoding="utf-8") as f:f.write(data.client_private_key.strip()+"\n")
   os.chmod(private_path,0o600)
   subprocess.run(["ip","link","del","wg-smoke"],capture_output=True,text=True,timeout=10)
   subprocess.run(["ip","link","add","wg-smoke","type","wireguard"],capture_output=True,text=True,timeout=10,check=True)
   subprocess.run(["ip","addr","add",str(addr),"dev","wg-smoke"],capture_output=True,text=True,timeout=10,check=True)
   subprocess.run(["wg","set","wg-smoke","private-key",private_path,"peer",data.server_public_key.strip(),"allowed-ips","0.0.0.0/0","endpoint",data.endpoint,"persistent-keepalive","1"],capture_output=True,text=True,timeout=10,check=True)
   subprocess.run(["ip","link","set","wg-smoke","up"],capture_output=True,text=True,timeout=10,check=True)
   endpoint_host=data.endpoint.rsplit(":",1)[0]
   endpoint_ip=ipaddress.ip_address(endpoint_host)
   route_to_endpoint=subprocess.run(["ip","route","get",str(endpoint_ip)],capture_output=True,text=True,timeout=10,check=True).stdout
   main_route=route_to_endpoint.splitlines()[0].split()
   endpoint_dev=main_route[main_route.index("dev")+1] if "dev" in main_route else ""
   endpoint_src=main_route[main_route.index("src")+1] if "src" in main_route else ""
   if not endpoint_dev: raise RuntimeError("Could not determine Node route to WireGuard endpoint")
   subprocess.run(["ip","route","replace","127.0.0.1/32","dev","lo","table","51820"],capture_output=True,text=True,timeout=10,check=True)
   gateway=main_route[main_route.index("via")+1] if "via" in main_route else ""
   if endpoint_src and gateway:
    # The policy table has no connected route to the WAN gateway. Use onlink so
    # the endpoint exemption can be installed without first cloning the WAN
    # subnet into table 51820. This keeps the WireGuard server endpoint reachable
    # while traffic from the smoke client is policy-routed through wg-smoke.
    subprocess.run(["ip","route","replace",f"{endpoint_ip}/32","via",gateway,"dev",endpoint_dev,"src",endpoint_src,"onlink","table","51820"],capture_output=True,text=True,timeout=10,check=True)
   elif endpoint_src:
    subprocess.run(["ip","route","replace",f"{endpoint_ip}/32","dev",endpoint_dev,"src",endpoint_src,"table","51820"],capture_output=True,text=True,timeout=10,check=True)
   else:
    subprocess.run(["ip","route","replace",f"{endpoint_ip}/32","dev",endpoint_dev,"table","51820"],capture_output=True,text=True,timeout=10,check=True)
   subprocess.run(["ip","route","replace","default","dev","wg-smoke","table","51820"],capture_output=True,text=True,timeout=10,check=True)
   subprocess.run(["ip","rule","add","priority","100","from",f"{addr.ip}/32","table","51820"],capture_output=True,text=True,timeout=10)
   route_check=subprocess.run(["ip","route","get","1.1.1.1","from",str(addr.ip)],capture_output=True,text=True,timeout=10)
   if route_check.returncode!=0: raise RuntimeError("Smoke client policy route failed: "+(route_check.stderr.strip() or route_check.stdout.strip()))
   handshake=0
   for _ in range(20):
    p=subprocess.run(["wg","show","wg-smoke","latest-handshakes"],capture_output=True,text=True,timeout=5,check=True)
    vals=p.stdout.split()
    handshake=int(vals[1]) if len(vals)>=2 else 0
    if handshake: break
    time.sleep(0.5)
   if not handshake: raise RuntimeError("Smoke client handshake did not complete")
   p=subprocess.run(["wg","show","wg-smoke","transfer"],capture_output=True,text=True,timeout=5,check=True)
   parts=p.stdout.split(); before_rx=int(parts[1]) if len(parts)>=2 else 0; before_tx=int(parts[2]) if len(parts)>=3 else 0
   ping=subprocess.run(["ping","-4","-c","2","-W","3","-I","wg-smoke","1.1.1.1"],capture_output=True,text=True,timeout=10)
   curl=subprocess.run(["curl","-4","-fsS","--interface","wg-smoke","--max-time","10","https://api.ipify.org"],capture_output=True,text=True,timeout=15)
   p=subprocess.run(["wg","show","wg-smoke","transfer"],capture_output=True,text=True,timeout=5,check=True)
   parts=p.stdout.split(); after_rx=int(parts[1]) if len(parts)>=2 else 0; after_tx=int(parts[2]) if len(parts)>=3 else 0
   if ping.returncode!=0: raise RuntimeError("Smoke client reached WireGuard but Internet ping failed: "+(ping.stderr.strip() or ping.stdout.strip()))
   if curl.returncode!=0 or not curl.stdout.strip(): raise RuntimeError("Smoke client Internet HTTPS failed: "+(curl.stderr.strip() or curl.stdout.strip()))
   if after_rx<=before_rx or after_tx<=before_tx: raise RuntimeError(f"Smoke client handshake exists but tunnel counters did not increase (rx {before_rx}->{after_rx}, tx {before_tx}->{after_tx})")
   return {"status":"TRAFFIC_VERIFIED","handshake":handshake,"rx_bytes":after_rx,"tx_bytes":after_tx,"internet_ipv4":curl.stdout.strip()}
  finally:
   subprocess.run(["ip","rule","del","priority","100","from",f"{addr.ip}/32","table","51820"],capture_output=True,text=True,timeout=10)
   subprocess.run(["ip","link","del","wg-smoke"],capture_output=True,text=True,timeout=10)
   subprocess.run(["ip","route","del","default","dev","wg-smoke","table","51820"],capture_output=True,text=True,timeout=10)
   subprocess.run(["ip","route","del","127.0.0.1/32","dev","lo","table","51820"],capture_output=True,text=True,timeout=10)
   subprocess.run(["ip","route","del",f"{endpoint_ip}/32","table","51820"],capture_output=True,text=True,timeout=10)
   try: os.unlink(private_path)
   except FileNotFoundError: pass
 except subprocess.CalledProcessError as e:
  raise HTTPException(502,e.stderr.strip() or e.stdout.strip() or str(e))
 except Exception as e:
  raise HTTPException(502,str(e))

@app.get("/diagnostics/preflight")
def diagnostics_preflight(x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"read")
 checks=[];issues=[]
 def check(name,ok,detail,critical=True):
  item={"name":name,"ok":bool(ok),"detail":str(detail),"critical":bool(critical)}
  checks.append(item)
  if critical and not ok: issues.append(item)
 def run(cmd,timeout=10):
  try:
   p=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout)
   return p.returncode,p.stdout.strip(),p.stderr.strip()
  except Exception as e:return 99,"",str(e)
 # SYSTEM
 check("systemd",shutil.which("systemctl") is not None,"systemctl available")
 check("python3",shutil.which("python3") is not None,"python3 available")
 check("openssl",shutil.which("openssl") is not None,"openssl available")
 check("ntp",os.path.exists("/run/systemd/timesync/synchronized") or (run(["timedatectl","show","-p","NTPSynchronized","--value"])[1]=="yes"),"clock synchronization detected",False)
 # NETWORK
 rc,default,_=run(["ip","route","show","default"])
 check("default_route",rc==0 and bool(default)," ".join(default.split()) or "no default route")
 wan=""
 m=re.search(r"\bdev\s+(\S+)",default)
 if m:wan=m.group(1)
 check("wan_interface",bool(wan),wan or "WAN interface not detected")
 source_ip=""
 if shutil.which("ip"):
  rc,out,err=run(["ip","route","get","1.1.1.1"])
  m=re.search(r"\bsrc\s+(\S+)",out);source_ip=m.group(1) if m else ""
 check("egress_source",bool(source_ip),source_ip or "could not determine egress source IP")
 rc,out,err=run(["getent","ahostsv4","example.com"])
 check("dns_resolution",rc==0 and bool(out),"DNS resolution works" if rc==0 and out else (err or "DNS resolution failed"))
 rc,out,err=run(["curl","-4","-fsS","--max-time","8","https://api.ipify.org"])
 public_ip=out.strip()
 check("https_egress",rc==0 and bool(public_ip),("public IPv4 "+public_ip) if public_ip else (err or "HTTPS egress failed"))
 # KERNEL / FORWARDING
 forwarding=open("/proc/sys/net/ipv4/ip_forward").read().strip() if os.path.exists("/proc/sys/net/ipv4/ip_forward") else "missing"
 check("ipv4_forwarding",forwarding=="1","net.ipv4.ip_forward="+forwarding)
 rp="/proc/sys/net/ipv4/conf/all/rp_filter"
 rp_value=open(rp).read().strip() if os.path.exists(rp) else "missing"
 check("rp_filter",rp_value in {"0","2"},"net.ipv4.conf.all.rp_filter="+rp_value,False)
 # WIREGUARD
 wg_ok=shutil.which("wg") is not None and shutil.which("wg-quick") is not None
 check("wireguard_tools",wg_ok,"wg/wg-quick installed" if wg_ok else "wg and/or wg-quick missing")
 awg_ok=shutil.which("awg") is not None and shutil.which("awg-quick") is not None
 check("amneziawg_tools",awg_ok,"awg/awg-quick installed" if awg_ok else "awg and/or awg-quick missing",False)
 if awg_ok and shutil.which("modprobe"):
  subprocess.run(["modprobe","amneziawg"],capture_output=True,text=True,timeout=30)
 check("amneziawg_kernel",os.path.exists("/sys/module/amneziawg"),"AmneziaWG kernel module available" if os.path.exists("/sys/module/amneziawg") else "AmneziaWG kernel module not loaded",False)
 rc,mods,_=run(["sh","-c","command -v modprobe >/dev/null && modprobe wireguard >/dev/null 2>&1; lsmod | grep '^wireguard ' || true"])
 check("wireguard_kernel",rc==0 and ("wireguard" in mods or os.path.exists("/sys/module/wireguard")),"WireGuard kernel module available",False)
 # FIREWALL
 fw_tool=shutil.which("iptables") or shutil.which("nft")
 check("firewall_tool",bool(fw_tool),str(fw_tool or "iptables/nft unavailable"))
 rc,iptables,_=run(["iptables","-L","FORWARD","-n","-v"],10) if shutil.which("iptables") else (99,"","iptables missing")
 check("forward_chain_readable",rc==0, "FORWARD chain readable" if rc==0 else (iptables or "unable to read FORWARD chain"),False)
 # SERVICE
 service_state=""
 if shutil.which("systemctl"):
  rc,service_state,_=run(["systemctl","is-active","primevpn-node-agent.service"])
 check("agent_service",service_state=="active","Node Agent systemd service active" if service_state=="active" else "Node Agent service is not active")
 rc,agent_port,_=run(["sh","-c","printf '%s\\n' \"$(grep '^PORT=' /etc/primevpn/agent.env 2>/dev/null | cut -d= -f2)\""])
 check("agent_port",bool(agent_port),"Agent TCP port="+agent_port if agent_port else "Agent port not configured",False)
 # Runtime interfaces are reported, but absence is not fatal before the panel applies a WireGuard inbound.
 interfaces=[]
 if shutil.which("wg"):
  rc,out,err=run(["wg","show","interfaces"])
  interfaces=out.split() if rc==0 else []
 check("wireguard_runtime",bool(interfaces),"WireGuard runtime interfaces: "+(",".join(interfaces) if interfaces else "none"),False)
 # Critical readiness means the node can be used; client traffic is deliberately NOT inferred here.
 ready=not issues
 return {"ready":ready,"version":VERSION,"checks":checks,"issues":issues,
         "observed":{"public_ipv4":public_ip or None,"egress_source":source_ip or None,"wan_interface":wan or None,
                     "default_route":default or None,"forwarding":forwarding,"rp_filter":rp_value,
                     "wireguard_interfaces":interfaces,"agent_service":service_state or None},
         "traffic":{"client_traffic_verified":False,"reason":"No client/inbound runtime traffic was supplied to this preflight"},
         "summary":"NODE READY: infrastructure baseline passed" if ready else "NODE NOT READY: critical preflight checks failed"}

@app.get("/diagnostics/wireguard/{interface}/{port}")
def wireguard_diagnostics(interface:str,port:int,protocol:str="wireguard",x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"read");safe_interface(interface)
 if port<1 or port>65535: raise HTTPException(400,"Invalid UDP port")
 if protocol not in {"wireguard","amneziawg"}: raise HTTPException(400,"Invalid WireGuard protocol")
 try: runtime=_wg_dump(interface,protocol)
 except Exception as e: runtime={"error":str(e),"public_key":None,"listen_port":None,"peers":[]}
 iptables_rules=[];forward_rules=[];nat_rules=[]
 if shutil.which("iptables"):
  p=subprocess.run(["iptables","-L","INPUT","-v","-n","-x"],capture_output=True,text=True,timeout=10)
  for line in p.stdout.splitlines():
   if "udp" in line and f"dpt:{port}" in line: iptables_rules.append(line.strip())
  p=subprocess.run(["iptables","-L","FORWARD","-v","-n","-x"],capture_output=True,text=True,timeout=10)
  forward_rules=[line.strip() for line in p.stdout.splitlines() if interface in line]
  p=subprocess.run(["iptables","-t","nat","-L","POSTROUTING","-v","-n","-x"],capture_output=True,text=True,timeout=10)
  nat_rules=[line.strip() for line in p.stdout.splitlines() if "MASQUERADE" in line]
 nft_lines=[]
 if shutil.which("nft"):
  p=subprocess.run(["nft","-a","list","ruleset"],capture_output=True,text=True,timeout=10)
  for line in p.stdout.splitlines():
   if "udp" in line and str(port) in line: nft_lines.append(line.strip())
 route=subprocess.run(["ip","route","show","default"],capture_output=True,text=True,timeout=10) if shutil.which("ip") else None
 iface_addr=subprocess.run(["ip","-o","addr","show","dev",interface],capture_output=True,text=True,timeout=10) if shutil.which("ip") else None
 iface_route=subprocess.run(["ip","route","show","dev",interface],capture_output=True,text=True,timeout=10) if shutil.which("ip") else None
 return {"interface":interface,"configured_port":port,"live_port":runtime.get("listen_port"),"live_public_key":runtime.get("public_key"),"peer_count":len(runtime.get("peers",[])),"peers":runtime.get("peers",[]),"iptables_input_matches":iptables_rules,"iptables_forward_matches":forward_rules,"iptables_masquerade_matches":nat_rules,"nft_udp_port_matches":nft_lines[:20],"default_route":(route.stdout.strip() if route and route.returncode==0 else None),"interface_addresses":(iface_addr.stdout.strip() if iface_addr and iface_addr.returncode==0 else None),"interface_routes":(iface_route.stdout.strip() if iface_route and iface_route.returncode==0 else None),"runtime_error":runtime.get("error")}

@app.get("/counters/wireguard/{interface}")
def counters(interface:str,protocol:str="wireguard",x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"read");safe_interface(interface)
 if protocol not in {"wireguard","amneziawg"}: raise HTTPException(400,"Invalid WireGuard protocol")
 tool="awg" if protocol=="amneziawg" else "wg"
 if not shutil.which(tool):raise HTTPException(503,f"{tool} unavailable")
 p=subprocess.run([tool,"show",interface,"dump"],capture_output=True,text=True,timeout=10)
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
 protocol:str="wireguard"
@app.post("/peers/revoke")
def revoke_peer(data:RevokePeer,x_agent_token:str|None=Header(default=None)):
 auth(x_agent_token,"write");safe_interface(data.interface)
 if data.protocol not in {"wireguard","amneziawg"}: raise HTTPException(400,"Invalid WireGuard protocol")
 tool="awg" if data.protocol=="amneziawg" else "wg"
 if not shutil.which(tool):raise HTTPException(503,f"{tool} unavailable")
 p=subprocess.run([tool,"set",data.interface,"peer",data.public_key,"remove"],capture_output=True,text=True,timeout=15)
 if p.returncode:raise HTTPException(502,p.stderr.strip() or "Peer revoke failed")
 path=f"/etc/primevpn/{data.interface}.conf"
 if os.path.exists(path):
  with open(path,encoding="utf-8") as f:config=without_peer(f.read(),data.public_key)
  with open(path+".new","w",encoding="utf-8") as f:f.write(config)
  os.chmod(path+".new",0o600);os.replace(path+".new",path)
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
   if shutil.which("systemctl"):
    subprocess.run(["systemctl","disable","--now",f"primevpn-wireguard-{name}.service"],capture_output=True,text=True,timeout=20)
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
