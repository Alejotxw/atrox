from functools import lru_cache

from pydantic import field_validator
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

    # CORS: origenes permitidos para que el frontend (Vite, otro puerto/origen)
    # pueda llamar a la API desde el navegador. Override vía env como JSON,
    # ej. ATROX_CORS_ORIGINS='["http://localhost:5173","http://otro:4000"]'.
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    nmap_path: str = "nmap"
    # Host-timeout Nmap (puertos web por defecto — no barrer 1-1024).
    nmap_timeout_seconds: int = 60
    nuclei_path: str = "nuclei"
    # Tope del vulnscan; con accept_partial el job NO falla al truncar.
    nuclei_timeout_seconds: int = 300
    nuclei_sandbox_templates: str | None = None
    # Si se define, Nuclei corre vía `docker run --rm -i <imagen>` en vez del
    # binario nativo (ej. "projectdiscovery/nuclei:latest") — útil cuando un
    # antivirus bloquea el ejecutable nativo de Nuclei en Windows.
    nuclei_docker_image: str | None = None
    # Volumen con nombre donde persiste nuclei-templates entre ejecuciones en
    # modo Docker — sin esto, cada contenedor `--rm` re-descarga el catálogo
    # completo (varios minutos) en cada escaneo. None desactiva el montaje.
    nuclei_docker_templates_volume: str | None = "atrox-nuclei-templates"
    # Rendimiento Nuclei
    nuclei_concurrency: int = 80
    nuclei_rate_limit: int = 200
    nuclei_request_timeout: int = 3
    nuclei_retries: int = 0
    nuclei_max_host_error: int = 8
    nuclei_exclude_tags: list[str] = ["dos", "fuzz", "intrusive"]
    nuclei_accept_partial_on_timeout: bool = True
    # Protocolos por defecto si el job no especifica type/protocols.
    nuclei_default_protocols: list[str] = ["http"]
    # Puertos por defecto del discovery si el job no envía port_range.
    nmap_default_port_range: str = "80,443,8080,8443"

    @field_validator("nmap_path", "nuclei_path", mode="before")
    @classmethod
    def _clean_tool_path(cls, value: object) -> object:
        """Quita comillas/espacios que rompen rutas de Windows en .env."""
        if not isinstance(value, str):
            return value
        cleaned = value.strip().strip('"').strip("'").strip()
        return cleaned or value

    # Cola de trabajos (HU-004)
    max_concurrent_scans: int = 10
    queue_max_size: int = 50
    parse_workers: int = 2

    # Cifrado en reposo (HU-007 / ADR-003) — nunca commitear la llave real
    encryption_master_key: str | None = None
    encrypted_storage_path: str = "data/encrypted"

    # Log de auditoría inmutable (HU-008 / ADR-003)
    audit_signing_key: str | None = None
    audit_log_path: str = "data/audit.log"
    audit_retention_days: int = 365

    # Scoring de confianza / falsos positivos (HU-016 / RF-005)
    fp_score_threshold: int = 40

    # Marcado manual de falsos positivos (HU-022)
    false_positive_store_path: str = "data/false_positives.jsonl"

    # Validación estructurada de respuestas IA (HU-017 / ADR-002)
    llm_validation_max_retries: int = 1
    llm_rejection_log_path: str | None = None

    # Abstracción de proveedores LLM (HU-012 / ADR-005)
    # "gemini" (Cloud) | "ollama" (local) | "mock" (default: tests/desarrollo)
    llm_provider: str = "mock"
    llm_model: str | None = None
    llm_api_key: str | None = None
    # 180s: modelos locales (llama3/etc.) suelen superar 30s en el primer
    # análisis; un timeout corto cortaba la auditoría con error de red.
    llm_timeout_seconds: int = 180
    llm_gemini_model: str = "gemini-2.0-flash"
    llm_ollama_base_url: str = "http://localhost:11434"
    llm_ollama_model: str = "llama3"
    # Limita tokens de salida en Ollama para acortar latencia de generación.
    llm_ollama_num_predict: int = 640
    # Contexto más chico = menos RAM/CPU por request en modelos locales.
    llm_ollama_num_ctx: int = 4096
    # Mantiene el modelo cargado entre llamadas (evita recargas lentas).
    llm_ollama_keep_alive: str = "10m"
    llm_fallback_providers: list[str] = []

    # Sincronización diaria de base de amenazas NVD (HU-005 / RF-010)
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None
    nvd_request_timeout_seconds: int = 30
    nvd_sync_interval_hours: int = 24
    nvd_sync_enabled: bool = True
    nvd_sync_on_startup: bool = False
    nvd_store_path: str = "data/threat_intel/cves.jsonl"
    nvd_sync_status_path: str = "data/threat_intel/last_sync.json"

    # Autenticación MFA para panel de administración (HU-018 / RNF-002)
    admin_username: str = "sysadmin"
    admin_password: str = "AtroxAdmin2026!"
    totp_secret: str | None = None
    session_ttl_minutes: int = 60
    mfa_max_failed_attempts: int = 5
    mfa_lockout_minutes: int = 15
    mfa_required: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
