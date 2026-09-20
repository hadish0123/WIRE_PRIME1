from sqlalchemy import create_engine,text,event
from sqlalchemy.orm import DeclarativeBase,sessionmaker,Session
from .config import settings

engine=create_engine(settings.database_url,pool_pre_ping=True,future=True)
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False,expire_on_commit=False)

class Base(DeclarativeBase):
    pass

@event.listens_for(Session,"after_begin")
def apply_rls_context(session,transaction,connection):
    context=session.info
    if context.get("is_platform"):
        connection.execute(text("select set_config('app.is_platform','true',true)"))
        connection.execute(text("select set_config('app.tenant_id','',true)"))
    elif context.get("tenant_id"):
        connection.execute(text("select set_config('app.is_platform','false',true)"))
        connection.execute(
            text("select set_config('app.tenant_id',:tenant,true)"),
            {"tenant":str(context["tenant_id"])},
        )

def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()

def set_platform_context(db):
    db.info["is_platform"]=True
    db.info.pop("tenant_id",None)
    db.execute(text("select set_config('app.is_platform','true',true)"))
    db.execute(text("select set_config('app.tenant_id','',true)"))

def set_tenant_context(db,tenant_id):
    db.info["is_platform"]=False
    db.info["tenant_id"]=str(tenant_id)
    db.execute(text("select set_config('app.is_platform','false',true)"))
    db.execute(
        text("select set_config('app.tenant_id',:tenant,true)"),
        {"tenant":str(tenant_id)},
    )
