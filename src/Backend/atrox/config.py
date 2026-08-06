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

    # CORS: origenes permitidos para que el frontend (Vite, otro puerto/origen)
    # pueda llamar a la API desde el navegador. Override vía env como JSON,
    # ej. ATROX_CORS_ORIGINS='["http://localhost:5173","http://otro:4000"]'.
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    nmap_path: str = "nmap"
    nmap_timeout_seconds: int = 300
    nuclei_path: str = "nuclei"
    # 480s (8min) da margen para la primera corrida antes de que el volumen
    # de plantillas esté "caliente" — con el volumen ya poblado, escaneos
    # posteriores terminan en una fracción de este tiempo.
    nuclei_timeout_seconds: int = 480
    nuclei_sandbox_templates: str | None = None
    # Si se define, Nuclei corre vía `docker run --rm -i <imagen>` en vez del
    # binario nativo (ej. "projectdiscovery/nuclei:latest") — útil cuando un
    # antivirus bloquea el ejecutable nativo de Nuclei en Windows.
    nuclei_docker_image: str | None = None
    # Volumen con nombre donde persiste nuclei-templates entre ejecuciones en
    # modo Docker — sin esto, cada contenedor `--rm` re-descarga el catálogo
    # completo (varios minutos) en cada escaneo. None desactiva el montaje.
    nuclei_docker_templates_volume: str | None = "atrox-nuclei-templates"

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
    llm_timeout_seconds: int = 30
    llm_gemini_model: str = "gemini-2.0-flash"
    llm_ollama_base_url: str = "http://localhost:11434"
    llm_ollama_model: str = "llama3"
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
