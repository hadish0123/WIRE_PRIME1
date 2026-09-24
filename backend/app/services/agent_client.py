import httpx,re
from ..security import create_agent_token
from .credentials import wg_public_key

def _url(node,path): return node.agent_url.rstrip("/")+"/"+path.lstrip("/")

def call(node,method,path,payload=None,timeout=30):
    if not node.agent_url: raise RuntimeError("Node agent URL is not configured")
    token=create_agent_token(node.id,node.tenant_id,["read","write"])
    headers={"X-Agent-Token":token}
    with httpx.Client(timeout=timeout,verify=False) as c:
        try:
            r=c.request(method,_url(node,path),json=payload,headers=headers)
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            body=e.response.text.strip()
            detail=f"{e.response.status_code} {body}" if body else str(e)
            raise RuntimeError(f"Node agent {method} {path} failed: {detail}") from e
        except httpx.HTTPError as e:
            raise RuntimeError(f"Node agent {method} {path} connection failed: {e}") from e

def _listen_port(config):
    import re
    m=re.search(r"(?m)^ListenPort\s*=\s*(\d+)\s*$",config)
    if not m: raise RuntimeError("WireGuard ListenPort missing from rendered configuration")
    return int(m.group(1))

def _expected_wireguard(config):
    private_match=re.search(r"(?m)^PrivateKey\s*=\s*(\S+)\s*$",config)
    expected_public=wg_public_key(private_match.group(1)) if private_match else None
    peers=[]
    for block in re.split(r"(?m)^\[Peer\]\s*$",config)[1:]:
        public=re.search(r"(?m)^PublicKey\s*=\s*(\S+)\s*$",block)
        allowed=re.search(r"(?m)^AllowedIPs\s*=\s*([^\n]+)$",block)
        if public:
            peers.append((public.group(1).strip(),allowed.group(1).strip() if allowed else ""))
    return expected_public,peers

def _validate_wireguard(node,protocol,interface,config):
    expected_port=_listen_port(config)
    diag=call(node,"GET",f"diagnostics/wireguard/{interface}/{expected_port}?protocol={protocol}",None,20)
    if diag.get("runtime_error"):
        raise RuntimeError("Node WireGuard runtime diagnostic failed: "+str(diag["runtime_error"]))
    live_port=int(diag.get("live_port") or 0)
    if live_port != expected_port:
        raise RuntimeError(f"Node WireGuard listen port mismatch: expected {expected_port} got {diag.get('live_port')}")
    expected_public,expected_peers=_expected_wireguard(config)
    address_match=re.search(r"(?m)^Address\s*=\s*([^\n]+)",config)
    expected_address=(address_match.group(1).split(",")[0].strip() if address_match else "")
    if expected_address and expected_address not in str(diag.get("interface_addresses") or ""):
        raise RuntimeError(f"Node WireGuard interface address mismatch: expected {expected_address} got {diag.get('interface_addresses')}")
    if expected_public and diag.get("live_public_key")!=expected_public:
        raise RuntimeError("Node WireGuard public key does not match the rendered server private key")
    live={str(p.get("public_key") or ""):p for p in (diag.get("peers") or [])}
    for public,allowed in expected_peers:
        peer=live.get(public)
        if not peer:
            raise RuntimeError(f"Node WireGuard peer is missing after apply: {public}")
        live_allowed={x.strip() for x in str(peer.get("allowed_ips") or "").split(",") if x.strip()}
        expected_allowed={x.strip() for x in allowed.split(",") if x.strip()}
        if expected_allowed and live_allowed!=expected_allowed:
            raise RuntimeError(f"Node WireGuard AllowedIPs mismatch for peer {public}: expected {sorted(expected_allowed)} got {sorted(live_allowed)}")
    if "iptables_forward_matches" in diag and not diag.get("iptables_forward_matches"):
        raise RuntimeError("Node WireGuard forwarding rules are missing")
    if "iptables_masquerade_matches" in diag and not diag.get("iptables_masquerade_matches"):
        raise RuntimeError("Node WireGuard MASQUERADE rule is missing")
    return diag

def apply(node,protocol,interface,config,files=None):
    payload={"protocol":protocol,"interface":interface,"config":config,"files":files or {}}
    apply_timeout=600 if protocol=="amneziawg" else 60
    result=call(node,"POST","apply",payload,apply_timeout)
    if protocol in {"wireguard","amneziawg"}:
        try:
            _validate_wireguard(node,protocol,interface,config)
            return result
        except Exception as first_error:
            # A stale wg0 runtime or a transient syncconf state must never make
            # node registration fail after the Agent already accepted the config.
            # Reconcile from a clean interface, then validate the live runtime
            # again. This is deliberately done for every WireGuard validation
            # failure, not only HTTP 502 responses.
            try:
                call(node,"POST","remove",{"protocol":protocol,"interface":interface},60)
                retry_result=call(node,"POST","apply",payload,apply_timeout)
                _validate_wireguard(node,protocol,interface,config)
                return retry_result
            except Exception as retry_error:
                raise RuntimeError(f"{first_error}; clean re-apply failed: {retry_error}") from retry_error
    return result

def revoke_wireguard_peer(node,interface,public_key,protocol="wireguard"):
    return call(node,"POST","peers/revoke",{"interface":interface,"public_key":public_key,"protocol":protocol})

def deploy_openvpn_crl(node,instance,crl_pem):
    return call(node,"POST","openvpn/crl",{"instance":instance,"crl_pem":crl_pem})

def apply_openvpn(node,instance,payload):
    return apply(node,"openvpn",instance,payload["config"],payload.get("files"))

def remove(node,protocol,interface):
    return call(node,"POST","remove",{"protocol":protocol,"interface":interface},60)
