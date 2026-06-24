from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración centralizada cargada desde variables de entorno."""

    model_config = SettingsConfigDict(
        env_prefix="ATROX_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    app_name: str = "Atrox API"
    host: str = "0.0.0.0"
    port: int = 8000
    env: str = "development"
    debug: bool = False
    nmap_path: str = "nmap"
    nmap_timeout_seconds: int = 300


@lru_cache
def get_settings() -> Settings:
    return Settings()
