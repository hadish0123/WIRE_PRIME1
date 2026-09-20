import httpx
from ..security import create_agent_token
def _url(node,path):return node.agent_url.rstrip("/")+"/"+path.lstrip("/")
def call(node,method,path,payload=None):
 if not node.agent_url:raise RuntimeError("Node agent URL is not configured")
 token=create_agent_token(node.id,node.tenant_id,["read","write"])
 headers={"X-Agent-Token":token}
 with httpx.Client(timeout=15,verify=True) as c:
  r=c.request(method,_url(node,path),json=payload,headers=headers);r.raise_for_status();return r.json()
def revoke_wireguard_peer(node,interface,public_key):
 return call(node,"POST","peers/revoke",{"interface":interface,"public_key":public_key})

def deploy_openvpn_crl(node,instance,crl_pem):
 return call(node,"POST","openvpn/crl",{"instance":instance,"crl_pem":crl_pem})

def apply_openvpn(node,instance,payload):
    return call(node,"POST","apply",{"protocol":"openvpn","interface":instance,"config":payload["config"],"files":payload["files"]})
