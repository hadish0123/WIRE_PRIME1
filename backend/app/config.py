from pydantic_settings import BaseSettings,SettingsConfigDict
class Settings(BaseSettings):
 app_name:str="PRIMEVPN"; version:str="100.0.0"; environment:str="development"
 database_url:str="postgresql+psycopg://primevpn:primevpn@localhost:5432/primevpn"
 jwt_secret:str="CHANGE_ME_IN_PRODUCTION"; jwt_algorithm:str="HS256"
 access_token_minutes:int=15; cors_origins:str="http://localhost:5173"
 model_config=SettingsConfigDict(env_file=".env",extra="ignore")
settings=Settings()