import httpx
from ..security import create_agent_token

def _url(node,path):
    return node.agent_url.rstrip("/")+"/"+path.lstrip("/")

def call(node,method,path,payload=None,timeout=30):
    if not node.agent_url:
        raise RuntimeError("Node agent URL is not configured")
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

def apply(node,protocol,interface,config,files=None):
    payload={"protocol":protocol,"interface":interface,"config":config,"files":files or {}}
    try:
        return call(node,"POST","apply",payload,60)
    except RuntimeError as first_error:
        if protocol in {"wireguard","amneziawg"} and "502" in str(first_error):
            try:
                call(node,"POST","remove",{"protocol":protocol,"interface":interface},60)
                return call(node,"POST","apply",payload,60)
            except Exception as retry_error:
                raise RuntimeError(f"{first_error}; clean re-apply failed: {retry_error}") from retry_error
        raise

def revoke_wireguard_peer(node,interface,public_key):
    return call(node,"POST","peers/revoke",{"interface":interface,"public_key":public_key})

def deploy_openvpn_crl(node,instance,crl_pem):
    return call(node,"POST","openvpn/crl",{"instance":instance,"crl_pem":crl_pem})

def apply_openvpn(node,instance,payload):
    return apply(node,"openvpn",instance,payload["config"],payload.get("files"))

def remove(node,protocol,interface):
    return call(node,"POST","remove",{"protocol":protocol,"interface":interface},60)
