import httpx
from ..security import create_agent_token

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

def _validate_wireguard(node,interface,config):
    expected_port=_listen_port(config)
    diag=call(node,"GET",f"diagnostics/wireguard/{interface}/{expected_port}",None,20)
    if diag.get("runtime_error"):
        raise RuntimeError("Node WireGuard runtime diagnostic failed: "+str(diag["runtime_error"]))
    live_port=int(diag.get("live_port") or 0)
    if live_port != expected_port:
        raise RuntimeError(f"Node WireGuard listen port mismatch: expected {expected_port} got {diag.get('live_port')}")
    peer_count=int(diag.get("peer_count") or 0)
    if peer_count < 1:
        raise RuntimeError("Node WireGuard has no installed peers after apply")
    return diag

def apply(node,protocol,interface,config,files=None):
    payload={"protocol":protocol,"interface":interface,"config":config,"files":files or {}}
    result=call(node,"POST","apply",payload,60)
    if protocol=="wireguard":
        try:
            _validate_wireguard(node,interface,config)
            return result
        except Exception as first_error:
            # A stale wg0 runtime or a transient syncconf state must never make
            # node registration fail after the Agent already accepted the config.
            # Reconcile from a clean interface, then validate the live runtime
            # again. This is deliberately done for every WireGuard validation
            # failure, not only HTTP 502 responses.
            try:
                call(node,"POST","remove",{"protocol":protocol,"interface":interface},60)
                retry_result=call(node,"POST","apply",payload,60)
                _validate_wireguard(node,interface,config)
                return retry_result
            except Exception as retry_error:
                raise RuntimeError(f"{first_error}; clean re-apply failed: {retry_error}") from retry_error
    return result

def revoke_wireguard_peer(node,interface,public_key):
    return call(node,"POST","peers/revoke",{"interface":interface,"public_key":public_key})

def deploy_openvpn_crl(node,instance,crl_pem):
    return call(node,"POST","openvpn/crl",{"instance":instance,"crl_pem":crl_pem})

def apply_openvpn(node,instance,payload):
    return apply(node,"openvpn",instance,payload["config"],payload.get("files"))

def remove(node,protocol,interface):
    return call(node,"POST","remove",{"protocol":protocol,"interface":interface},60)
