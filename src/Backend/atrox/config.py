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
    nuclei_path: str = "nuclei"
    nuclei_timeout_seconds: int = 300
    nuclei_sandbox_templates: str | None = None

    # Cola de trabajos (HU-004)
    max_concurrent_scans: int = 10
    queue_max_size: int = 50
    parse_workers: int = 2


@lru_cache
def get_settings() -> Settings:
    return Settings()
