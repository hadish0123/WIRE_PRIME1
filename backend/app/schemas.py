from datetime import datetime
from pydantic import BaseModel,Field,ConfigDict
from .models import Protocol,NodeState,ResourceState,RoleName
class LoginIn(BaseModel): email:str;password:str=Field(min_length=12,max_length=256)
class TokenOut(BaseModel): access_token:str;token_type:str="bearer";expires_in:int;mfa_required:bool=False;mfa_token:str|None=None
class TenantIn(BaseModel): name:str=Field(min_length=2,max_length=160);slug:str=Field(pattern=r"^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$")
class NodeIn(BaseModel): name:str=Field(min_length=2,max_length=160);address:str=Field(min_length=3,max_length=255);agent_url:str|None=Field(default=None,max_length=512)
class AutoNodeIn(BaseModel): name:str=Field(min_length=2,max_length=160);address:str=Field(min_length=3,max_length=255);ssh_port:int=Field(default=22,gt=0,lt=65536);ssh_username:str=Field(min_length=1,max_length=80);ssh_password:str=Field(min_length=1,max_length=512)
class InboundIn(BaseModel): node_id:str;name:str;protocol:Protocol;listen_port:int=Field(gt=0,lt=65536);interface:str;address:str;network:str;dns:str|None=None;mtu:int|None=Field(default=None,ge=576,le=9000)
class ClientIn(BaseModel):
 inbound_id:str
 name:str=Field(min_length=1,max_length=160)
 assigned_address:str
 expires_at:datetime|None=None
 total_bytes:int|None=Field(default=None,ge=1)
 daily_bytes:int|None=Field(default=None,ge=1)
 monthly_bytes:int|None=Field(default=None,ge=1)
 max_devices:int|None=Field(default=None,ge=1)
 warning_ratio:int=Field(default=80,ge=1,le=100)
class ClientUpdateIn(BaseModel):
 name:str|None=Field(default=None,min_length=1,max_length=160)
 expires_at:datetime|None=None
 total_bytes:int|None=Field(default=None,ge=1)
 daily_bytes:int|None=Field(default=None,ge=1)
 monthly_bytes:int|None=Field(default=None,ge=1)
 max_devices:int|None=Field(default=None,ge=1)
 warning_ratio:int|None=Field(default=None,ge=1,le=100)
class NodeOut(BaseModel): model_config=ConfigDict(from_attributes=True);id:str;name:str;address:str;agent_url:str|None;state:NodeState;agent_version:str|None;last_seen_at:datetime|None
class InboundOut(BaseModel): model_config=ConfigDict(from_attributes=True);id:str;node_id:str;name:str;protocol:Protocol;listen_port:int;interface:str;address:str;network:str;enabled:bool;desired_state:str
class ClientOut(BaseModel): model_config=ConfigDict(from_attributes=True);id:str;inbound_id:str;name:str;status:ResourceState;assigned_address:str;expires_at:datetime|None
class ClientDetailOut(BaseModel):
 id:str;inbound_id:str;inbound_name:str;protocol:Protocol;node_id:str;node_name:str;listen_port:int
 name:str;status:ResourceState;assigned_address:str;expires_at:datetime|None;created_at:datetime
 traffic_in:int;traffic_out:int;total_traffic:int
 quota_total:int|None;quota_daily:int|None;quota_monthly:int|None;quota_used:int;quota_state:str|None;quota_warning_ratio:int|None;quota_expires_at:datetime|None
 devices_count:int;online:bool;last_seen_at:datetime|None
class DeviceOut(BaseModel):
 id:str;client_id:str;fingerprint:str;assigned_address:str|None;last_seen_at:datetime|None
class MeOut(BaseModel): id:str;email:str;tenant_id:str|None;role:RoleName