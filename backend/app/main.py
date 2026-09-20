import uuid
from fastapi import FastAPI,Request
from fastapi.middleware.cors import CORSMiddleware
from .config import settings
app=FastAPI(title=settings.app_name,version=settings.version)
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.cors_origins.split(",")],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
@app.middleware("http")
async def request_context(request:Request,call_next):
 rid=request.headers.get("X-Request-ID") or str(uuid.uuid4());request.state.request_id=rid;response=await call_next(request);response.headers["X-Request-ID"]=rid;return response
@app.get("/healthz")
def healthz():return {"status":"ok","version":settings.version}
@app.get("/readyz")
def readyz():return {"status":"ready"}
from .routers import auth,tenants,nodes,inbounds,clients,traffic,audit,quotas,admins
app.include_router(auth.router,prefix="/api/v1/auth",tags=["auth"]);app.include_router(tenants.router,prefix="/api/v1/tenants",tags=["tenants"]);app.include_router(nodes.router,prefix="/api/v1/nodes",tags=["nodes"]);app.include_router(inbounds.router,prefix="/api/v1/inbounds",tags=["inbounds"]);app.include_router(clients.router,prefix="/api/v1/clients",tags=["clients"]);app.include_router(traffic.router,prefix="/api/v1/traffic",tags=["traffic"]);app.include_router(audit.router,prefix="/api/v1/audit",tags=["audit"]);app.include_router(quotas.router,prefix="/api/v1/quotas",tags=["quotas"]);app.include_router(admins.router,prefix="/api/v1/admins",tags=["admins"])