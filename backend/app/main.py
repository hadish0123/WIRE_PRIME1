import uuid
from fastapi import FastAPI,Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from .config import settings
app=FastAPI(title=settings.app_name,version=settings.version,docs_url="/docs",redoc_url="/redoc")
trusted=[x.strip() for x in settings.trusted_hosts.split(",") if x.strip()]
if trusted: app.add_middleware(TrustedHostMiddleware,allowed_hosts=trusted)

app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()],allow_credentials=True,allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],allow_headers=["Authorization","Content-Type","Idempotency-Key","X-Request-ID"])
@app.middleware("http")
async def request_context(request:Request,call_next):
 rid=request.headers.get("X-Request-ID") or str(uuid.uuid4());request.state.request_id=rid
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
from .routers import auth,tenants,nodes,inbounds,clients,traffic,audit,quotas,admins,provisioning,configs,credentials,commerce
for router,prefix,tags in [(auth.router,"/api/v1/auth",["auth"]),(tenants.router,"/api/v1/tenants",["tenants"]),(nodes.router,"/api/v1/nodes",["nodes"]),(inbounds.router,"/api/v1/inbounds",["inbounds"]),(clients.router,"/api/v1/clients",["clients"]),(traffic.router,"/api/v1/traffic",["traffic"]),(audit.router,"/api/v1/audit",["audit"]),(quotas.router,"/api/v1/quotas",["quotas"]),(admins.router,"/api/v1/admins",["admins"]),(provisioning.router,"/api/v1/provisioning",["provisioning"]),(configs.router,"/api/v1/configs",["configs"]),(credentials.router,"/api/v1/credentials",["credentials"]),(commerce.router,"/api/v1/commerce",["commerce"])]:app.include_router(router,prefix=prefix,tags=tags)