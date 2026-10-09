from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    port: int = 3000
    database_url: str = 'sqlite:///./sentinelx-dev.db'
    manus_api_url: str | None = None
    manus_api_key: str | None = None
    manus_project_id: str | None = None
    manus_oauth_portal_url: str | None = None
    manus_oauth_api_url: str | None = None
    manus_jwt_secret: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
