import asyncio
import logging
import uuid
from fastapi import FastAPI,Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from .config import settings
from .db import SessionLocal, set_platform_context
from .models import Node, Inbound, Protocol, NodeState
from .services import agent_client

logger=logging.getLogger("primevpn.traffic")
app=FastAPI(title=settings.app_name,version=settings.version,docs_url="/docs",redoc_url="/redoc")
_traffic_task=None
_traffic_previous={}

async def _traffic_monitor():
    await asyncio.sleep(5)
    while True:
        db=SessionLocal()
        try:
            set_platform_context(db)
            nodes=db.query(Node).filter(Node.state.in_([NodeState.ready,NodeState.degraded])).all()
            for node in nodes:
                inbounds=db.query(Inbound).filter(Inbound.node_id==node.id,Inbound.enabled.is_(True),Inbound.desired_state=="ACTIVE").all()
                for inbound in inbounds:
                    if inbound.protocol not in {Protocol.wireguard,Protocol.amneziawg}:
                        continue
                    try:
                        data=agent_client.call(node,"GET",f"counters/wireguard/{inbound.interface}",timeout=10)
                        peers=data.get("peers") or []
                        logger.info("VPN_TRAFFIC node=%s inbound=%s interface=%s listen_port=%s peers=%s",node.id,inbound.id,inbound.interface,inbound.listen_port,len(peers))
                        for peer in peers:
                            key=(node.id,inbound.id,peer.get("public_key"))
                            current=(int(peer.get("bytes_received") or 0),int(peer.get("bytes_sent") or 0),int(peer.get("last_handshake") or 0))
                            previous=_traffic_previous.get(key)
                            delta_in=max(0,current[0]-(previous[0] if previous else current[0]))
                            delta_out=max(0,current[1]-(previous[1] if previous else current[1]))
                            logger.info("VPN_PEER node=%s inbound=%s peer=%s endpoint=%s handshake=%s rx=%s tx=%s delta_rx=%s delta_tx=%s",node.id,inbound.id,peer.get("public_key"),peer.get("endpoint"),current[2],current[0],current[1],delta_in,delta_out)
                            _traffic_previous[key]=current
                    except Exception as exc:
                        logger.warning("VPN_TRAFFIC_ERROR node=%s inbound=%s interface=%s error=%s",node.id,inbound.id,inbound.interface,exc)
        except Exception as exc:
            logger.exception("VPN_TRAFFIC_MONITOR_ERROR error=%s",exc)
        finally:
            db.close()
        await asyncio.sleep(10)

@app.on_event("startup")
async def start_traffic_monitor():
    global _traffic_task
    _traffic_task=asyncio.create_task(_traffic_monitor())

@app.on_event("shutdown")
async def stop_traffic_monitor():
    global _traffic_task
    if _traffic_task:
        _traffic_task.cancel()
        try:
            await _traffic_task
        except asyncio.CancelledError:
            pass
        _traffic_task=None

trusted=[x.strip() for x in settings.trusted_hosts.split(",") if x.strip()]

app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()],allow_credentials=True,allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],allow_headers=["Authorization","Content-Type","Idempotency-Key","X-Request-ID"])
@app.middleware("http")
async def request_context(request:Request,call_next):
 rid=request.headers.get("X-Request-ID") or str(uuid.uuid4());request.state.request_id=rid
 host=request.headers.get("host","").split(":")[0].strip().lower()
 if request.url.path!="/healthz":
  allowed=host in {h.lower() for h in trusted} or any(h.startswith("*.") and host.endswith(h[1:].lower()) for h in trusted)
  if not allowed:return PlainTextResponse("Invalid host",status_code=400)
 response=await call_next(request)
 response.headers["X-Request-ID"]=rid
 response.headers["X-Content-Type-Options"]="nosniff"
 response.headers["X-Frame-Options"]="DENY"
 response.headers["Referrer-Policy"]="no-referrer"
 response.headers["Permissions-Policy"]="geolocation=(),camera=(),microphone=()"
 return response
@app.get("/healthz")
def healthz():return {"status":"ok","version":settings.version}
@app.get("/readyz")
def readyz():return {"status":"ready"}
from .routers import auth,tenants,nodes,inbounds,clients,traffic,audit,quotas,admins,provisioning,configs,credentials,commerce,settings as settings_router
for router,prefix,tags in [(auth.router,"/api/v1/auth",["auth"]),(tenants.router,"/api/v1/tenants",["tenants"]),(nodes.router,"/api/v1/nodes",["nodes"]),(inbounds.router,"/api/v1/inbounds",["inbounds"]),(clients.router,"/api/v1/clients",["clients"]),(traffic.router,"/api/v1/traffic",["traffic"]),(audit.router,"/api/v1/audit",["audit"]),(quotas.router,"/api/v1/quotas",["quotas"]),(admins.router,"/api/v1/admins",["admins"]),(provisioning.router,"/api/v1/provisioning",["provisioning"]),(configs.router,"/api/v1/configs",["configs"]),(credentials.router,"/api/v1/credentials",["credentials"]),(commerce.router,"/api/v1/commerce",["commerce"]),(settings_router.router,"/api/v1/settings",["settings"])]:app.include_router(router,prefix=prefix,tags=tags)
