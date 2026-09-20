from sqlalchemy import create_engine,text
from sqlalchemy.orm import DeclarativeBase,sessionmaker
from .config import settings
engine=create_engine(settings.database_url,pool_pre_ping=True,future=True)
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False,expire_on_commit=False)
class Base(DeclarativeBase): pass
def get_db():
 db=SessionLocal()
 try:
  yield db
 finally:
  db.close()

def set_platform_context(db):
 db.execute(text("select set_config('app.is_platform','true',true)"))

def set_tenant_context(db,tenant_id):
 db.execute(text("select set_config('app.is_platform','false',true)"))
 db.execute(text("select set_config('app.tenant_id',:tenant,true)"),{"tenant":tenant_id})