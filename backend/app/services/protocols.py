import ipaddress,re
from dataclasses import dataclass
@dataclass(frozen=True)
class WireGuardPeer:
 public_key:str;allowed_ips:str;preshared_key:str|None=None;endpoint:str|None=None;keepalive:int|None=None
@dataclass(frozen=True)
class WireGuardConfig:
 private_key:str;listen_port:int;address:str;peers:tuple[WireGuardPeer,...]
def _key(v:str)->str:
 if not re.fullmatch(r"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480-9+/]{1,2}",v): raise ValueError("invalid key material")
 return v
def render_wireguard(c:WireGuardConfig)->str:
 ipaddress.ip_interface(c.address); 
 if not 1<=c.listen_port<=65535: raise ValueError("invalid listen port")
 lines=["[Interface]",f"PrivateKey = {_key(c.private_key)}",f"ListenPort = {c.listen_port}",f"Address = {c.address}"]
 for p in c.peers:
  _key(p.public_key);ipaddress.ip_network(p.allowed_ips,strict=False)
  lines += ["","[Peer]",f"PublicKey = {_key(p.public_key)}",f"AllowedIPs = {p.allowed_ips}"]
  if p.preshared_key: lines.append(f"PresharedKey = {_key(p.preshared_key)}")
  if p.endpoint: lines.append(f"Endpoint = {p.endpoint}")
  if p.keepalive is not None:
   if not 0<=p.keepalive<=65535: raise ValueError("invalid keepalive")
   lines.append(f"PersistentKeepalive = {p.keepalive}")
 return "\n".join(lines)+"\n"
def render_openvpn(server_network:str,port:int,transport:str="udp",tls_min:str="1.2",tls_crypt_path:str="/etc/primevpn/tls-crypt.key")->str:
 ipaddress.ip_network(server_network,strict=False)
 if not 1<=port<=65535 or transport not in {"udp","tcp"} or tls_min not in {"1.2","1.3"}:raise ValueError("invalid OpenVPN parameters")
 return "\n".join([f"port {port}",f"proto {transport}",f"server {server_network.split('/')[0]} {str(ipaddress.ip_network(server_network,strict=False).netmask)}","topology subnet","tls-version-min "+tls_min,"tls-crypt "+tls_crypt_path,"data-ciphers AES-256-GCM:AES-128-GCM","keepalive 10 60","persist-key","persist-tun","status /run/primevpn/openvpn.status 10","verb 3"])+"\n"
