from functools import lru_cache
from pathlib import Path

from fastapi import HTTPException, Request

from atrox.config import get_settings
from atrox.security.audit_service import AuditLogService, AuditLogStore
from atrox.security.audit_signer import AuditSigner, AuditSigningKeyError, decode_signing_key


def build_audit_log_service() -> AuditLogService:
    settings = get_settings()
    if not settings.audit_signing_key:
        raise AuditSigningKeyError(
            "ATROX_AUDIT_SIGNING_KEY no está configurada. "
            "Inyéctela únicamente vía variable de entorno en el despliegue."
        )

    store = AuditLogStore(
        log_path=Path(settings.audit_log_path),
        retention_days=settings.audit_retention_days,
    )
    signer = AuditSigner(decode_signing_key(settings.audit_signing_key))
    return AuditLogService(store=store, signer=signer)


@lru_cache
def get_audit_log_service_cached() -> AuditLogService:
    return build_audit_log_service()


def get_audit_log(request: Request) -> AuditLogService:
    """Obtiene el servicio de auditoría desde app.state (inicializado en lifespan)."""
    audit_log = getattr(request.app.state, "audit_log", None)
    if audit_log is None:
        raise HTTPException(
            status_code=503,
            detail="Servicio de auditoría no configurado. Defina ATROX_AUDIT_SIGNING_KEY.",
        )
    return audit_log
