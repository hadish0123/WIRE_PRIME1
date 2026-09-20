from pydantic_settings import BaseSettings,SettingsConfigDict
from pydantic import model_validator
class Settings(BaseSettings):
 app_name:str="PRIMEVPN"
 version:str="100.0.0"
 environment:str="development"
 database_url:str="postgresql+psycopg://primevpn:primevpn@localhost:5432/primevpn"
 jwt_secret:str="CHANGE_ME_IN_PRODUCTION"
 jwt_algorithm:str="HS256"
 access_token_minutes:int=15
 agent_access_minutes:int=10
 agent_signing_private_key:str=""
 data_encryption_key:str=""
 cors_origins:str="http://localhost:5173"
 model_config=SettingsConfigDict(env_file=".env",extra="ignore")
 @model_validator(mode="after")
 def validate_security(self):
  if self.environment=="production" and (self.jwt_secret=="CHANGE_ME_IN_PRODUCTION" or len(self.jwt_secret)<32):raise ValueError("Production JWT_SECRET must be a strong secret")
  if self.environment=="production" and not self.agent_signing_private_key:raise ValueError("Production agent signing key is required")
  if self.environment=="production" and not self.data_encryption_key:raise ValueError("Production data encryption key is required")
  return self
settings=Settings()
