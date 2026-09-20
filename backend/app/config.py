from pydantic_settings import BaseSettings,SettingsConfigDict\nfrom pydantic import model_validator
class Settings(BaseSettings):
 app_name:str="PRIMEVPN"; version:str="100.0.0"; environment:str="development"
 database_url:str="postgresql+psycopg://primevpn:primevpn@localhost:5432/primevpn"
 jwt_secret:str="CHANGE_ME_IN_PRODUCTION"; jwt_algorithm:str="HS256"
 access_token_minutes:int=15; cors_origins:str="http://localhost:5173"
 model_config=SettingsConfigDict(env_file=".env",extra="ignore")\n @model_validator(mode="after")\n def validate_security(self):\n  if self.environment=="production" and (self.jwt_secret=="CHANGE_ME_IN_PRODUCTION" or len(self.jwt_secret)<32): raise ValueError("Production JWT_SECRET must be a strong secret")\n  return self
settings=Settings()