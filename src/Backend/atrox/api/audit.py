from datetime import datetime

from fastapi import APIRouter, Depends, Header, Query

from atrox.security.audit_deps import get_audit_log
from atrox.security.audit_models import AuditEventCreate, AuditLogQueryResult, SignedAuditEntry
from atrox.security.audit_service import AuditLogService

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.post("/events", status_code=201, response_model=SignedAuditEntry)
async def record_audit_event(
    body: AuditEventCreate,
    audit: AuditLogService = Depends(get_audit_log),
    x_atrox_user: str | None = Header(default=None, alias="X-Atrox-User"),
) -> SignedAuditEntry:
    """Registra un evento de auditoría (escaneos, cambios de política, etc.)."""
    user = x_atrox_user or body.user
    return await audit.record(
        user=user,
        action=body.action,
        resource=body.resource,
        metadata=body.metadata,
    )


@router.get("/logs", response_model=AuditLogQueryResult)
async def query_audit_logs(
    from_date: datetime | None = Query(default=None, alias="from", description="ISO 8601 inicio"),
    to_date: datetime | None = Query(default=None, alias="to", description="ISO 8601 fin"),
    user: str | None = Query(default=None, description="Filtrar por usuario"),
    action: str | None = Query(default=None, description="Filtrar por acción"),
    audit: AuditLogService = Depends(get_audit_log),
) -> AuditLogQueryResult:
    """Consulta el log de auditoría filtrable por rango de fechas, usuario y acción."""
    entries, verified, tampered = await audit.query(
        from_date=from_date,
        to_date=to_date,
        user=user,
        action=action,
        verify=True,
    )
    return AuditLogQueryResult(
        total=len(entries),
        verified=verified,
        tampered=tampered,
        entries=entries,
    )


@router.get("/integrity")
async def verify_audit_integrity(
    audit: AuditLogService = Depends(get_audit_log),
) -> dict[str, object]:
    """Verifica integridad de todas las entradas (detección de alteración)."""
    tampered_ids = await audit.verify_integrity()
    return {
        "valid": len(tampered_ids) == 0,
        "tampered_count": len(tampered_ids),
        "tampered_ids": tampered_ids,
    }

