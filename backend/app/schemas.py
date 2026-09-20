from datetime import datetime
from pydantic import BaseModel,Field,ConfigDict
from .models import Protocol,NodeState,ResourceState,RoleName
class LoginIn(BaseModel): email:str;password:str=Field(min_length=12,max_length=256)
class TokenOut(BaseModel): access_token:str;token_type:str="bearer";expires_in:int;mfa_required:bool=False;mfa_token:str|None=None
class TenantIn(BaseModel): name:str=Field(min_length=2,max_length=160);slug:str=Field(pattern=r"^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$")
class NodeIn(BaseModel): name:str=Field(min_length=2,max_length=160);address:str=Field(min_length=3,max_length=255)
class InboundIn(BaseModel): node_id:str;name:str;protocol:Protocol;listen_port:int=Field(gt=0,lt=65536);interface:str;address:str;network:str;dns:str|None=None;mtu:int|None=Field(default=None,ge=576,le=9000)
class ClientIn(BaseModel): inbound_id:str;name:str;assigned_address:str;expires_at:datetime|None=None
class NodeOut(BaseModel): model_config=ConfigDict(from_attributes=True);id:str;name:str;address:str;state:NodeState;agent_version:str|None;last_seen_at:datetime|None
class InboundOut(BaseModel): model_config=ConfigDict(from_attributes=True);id:str;node_id:str;name:str;protocol:Protocol;listen_port:int;interface:str;address:str;network:str;enabled:bool;desired_state:str
class ClientOut(BaseModel): model_config=ConfigDict(from_attributes=True);id:str;inbound_id:str;name:str;status:ResourceState;assigned_address:str;expires_at:datetime|None
class MeOut(BaseModel): id:str;email:str;tenant_id:str|None;role:RoleName