"""Router de inteligencia de amenazas — catálogo NVD y sincronización (HU-005).

`POST /api/threats/sync` dispara una sincronización manual con la API NVD;
`GET /api/threats/last-sync` expone el log de la última sincronización
(DoD HU-005); `GET /api/threats/cves` consulta el catálogo indexado con
filtros y paginación, útil para correlación de hallazgos (RF-010).
"""

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel

from atrox.threat_intel.models import CVEEntry, CveSyncStatus
from atrox.threat_intel.service import NvdSyncService, SyncInProgressError

router = APIRouter(prefix="/api/threats", tags=["threats"])


class PaginatedCveCatalog(BaseModel):
    """Vista de página del catálogo de CVEs indexados desde NVD."""

    items: list[CVEEntry]
    total: int
    page: int
    page_size: int
    total_pages: int


def get_nvd_sync_service(request: Request) -> NvdSyncService:
    """Obtiene el servicio de sincronización NVD desde app.state."""
    service = getattr(request.app.state, "nvd_sync_service", None)
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="Servicio de sincronización NVD no inicializado",
        )
    return service


@router.post("/sync", status_code=202, response_model=CveSyncStatus)
async def trigger_sync(
    request: Request,
    force_full: bool = Query(
        default=False,
        description="Ignora la última sincronización y descarga el catálogo completo",
    ),
    service: NvdSyncService = Depends(get_nvd_sync_service),
    x_atrox_user: str | None = Header(default=None, alias="X-Atrox-User"),
) -> CveSyncStatus:
    """Ejecuta manualmente la sincronización con la API NVD (HU-005)."""
    try:
        status = await service.sync_once(force_full=force_full)
    except SyncInProgressError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    audit_log = getattr(request.app.state, "audit_log", None)
    if audit_log is not None:
        await audit_log.record(
            user=x_atrox_user or "system",
            action="threat.synced",
            resource="nvd:catalog",
            metadata={
                "status": status.status.value,
                "cves_total": status.cves_total,
                "cves_added": status.cves_added,
                "cves_updated": status.cves_updated,
            },
        )

    return status


@router.get("/last-sync", response_model=CveSyncStatus)
async def get_last_sync(
    service: NvdSyncService = Depends(get_nvd_sync_service),
) -> CveSyncStatus:
    """Consulta el log de la última sincronización NVD (DoD HU-005)."""
    return await service.get_status()


@router.get("/cves", response_model=PaginatedCveCatalog)
async def list_cves(
    cve_id: str | None = Query(default=None, description="Filtra por CVE-ID (subcadena)"),
    severity: str | None = Query(default=None, description="Filtra por severidad CVSS (ej. CRITICAL)"),
    q: str | None = Query(default=None, description="Búsqueda en la descripción"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    service: NvdSyncService = Depends(get_nvd_sync_service),
) -> PaginatedCveCatalog:
    """Consulta el catálogo de CVEs indexado desde NVD, paginado y filtrable."""
    store = service.store
    offset = (page - 1) * page_size
    items = await store.list_cves(
        cve_id=cve_id,
        severity=severity,
        query=q,
        limit=page_size,
        offset=offset,
    )
    total = await store.count(cve_id=cve_id, severity=severity, query=q)

    return PaginatedCveCatalog(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/cves/{cve_id}", response_model=CVEEntry)
async def get_cve(
    cve_id: str,
    service: NvdSyncService = Depends(get_nvd_sync_service),
) -> CVEEntry:
    """Consulta un CVE individual del catálogo por su ID."""
    entry = await service.store.get(cve_id.upper())
    if entry is None:
        raise HTTPException(
            status_code=404,
            detail=f"CVE {cve_id} no encontrado en el catálogo",
        )
    return entry
