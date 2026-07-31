"""Router REST unificado de escaneos: creación (HU-009) y consulta (HU-010).

`POST /api/scans` es una fachada pública sobre la cola de trabajos de
HU-004: valida el payload (objetivo + tipo de escaneo) y delega en
`JobQueue.submit`, exponiendo el identificador resultante como `scan_id`.

`GET /api/scans/{scan_id}` traduce el `Job` interno de HU-004 a una vista
de analista: progreso, activos descubiertos (escaneos `discovery`) y
hallazgos paginados y filtrables por severidad (escaneos `vulnscan`). Como
un `Job` es de un solo tipo, `assets` y `findings` son mutuamente
excluyentes según `scan_type`.

`POST /api/scans/{scan_id}/findings/false-positive` (HU-022) persiste el
marcado manual de un hallazgo como falso positivo (usuario + timestamp,
`atrox/findings/store.py`) y por eso `GET /api/scans/{scan_id}` excluye por
defecto los hallazgos ya marcados (`include_false_positives=true` para
verlos). `GET /api/scans/{scan_id}/findings/false-positives` expone el
dataset etiquetado resultante para reentrenamiento/heurística futura.
"""

from datetime import datetime
from math import ceil
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator

from atrox.api.jobs import get_job_queue
from atrox.findings.models import FalsePositiveMark, FalsePositiveMarkResponse, MarkFalsePositiveRequest
from atrox.findings.store import FalsePositiveStore
from atrox.queue.models import JobStatus, JobType
from atrox.queue.service import JobQueue, QueueFullError
from atrox.scanner.models import HostFinding, VulnFinding, VulnSeverity
from atrox.scanner.validators import validate_target

router = APIRouter(prefix="/api/scans", tags=["scans"])

# Progreso aproximado por estado: la cola (HU-004) no instrumenta avance
# granular dentro de un escaneo, asi que se deriva del ciclo de vida del Job.
_PROGRESS_BY_STATUS: dict[JobStatus, float] = {
    JobStatus.PENDING: 0.0,
    JobStatus.RUNNING: 0.5,
    JobStatus.DONE: 1.0,
    JobStatus.FAILED: 1.0,
}


# -- Modelos de request/response para la API --------------------------------


class ScanCreateRequest(BaseModel):
    """Payload para crear un nuevo escaneo."""

    target: str
    scan_type: JobType
    params: dict = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def check_target(cls, value: str) -> str:
        return validate_target(value)


class ScanCreateResponse(BaseModel):
    """Respuesta al crear un escaneo: ID y estado inicial."""

    scan_id: UUID
    status: str


class PaginatedFindings(BaseModel):
    """Página de hallazgos de un escaneo `vulnscan`."""

    items: list[VulnFinding]
    total: int
    page: int
    page_size: int
    total_pages: int


class ScanDetailResponse(BaseModel):
    """Vista de analista de un escaneo: progreso, activos y hallazgos."""

    scan_id: UUID
    scan_type: JobType
    status: JobStatus
    progress: float
    target: str
    assets: list[HostFinding]
    findings: PaginatedFindings
    error: str | None = None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


# -- Endpoints ----------------------------------------------------------------


@router.post("", status_code=202, response_model=ScanCreateResponse)
async def create_scan(
    body: ScanCreateRequest,
    request: Request,
    queue: JobQueue = Depends(get_job_queue),
    x_atrox_user: str | None = Header(default=None, alias="X-Atrox-User"),
) -> ScanCreateResponse:
    """Crea un escaneo y lo encola automáticamente en la cola de HU-004."""
    try:
        job = await queue.submit(
            job_type=body.scan_type,
            params={"target": body.target, **body.params},
        )
    except QueueFullError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    audit_log = getattr(request.app.state, "audit_log", None)
    if audit_log is not None:
        await audit_log.record(
            user=x_atrox_user or "system",
            action="scan.created",
            resource=f"scan:{job.id}",
            metadata={"scan_type": body.scan_type.value, "target": body.target},
        )

    return ScanCreateResponse(scan_id=job.id, status=job.status.value)


def get_false_positive_store(request: Request) -> FalsePositiveStore:
    """Obtiene la instancia de FalsePositiveStore desde app.state."""
    return request.app.state.false_positive_store


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_detail(
    scan_id: UUID,
    severity: VulnSeverity | None = Query(default=None, description="Filtra hallazgos por severidad"),
    asset_status: str | None = Query(default=None, description="Filtra activos por estado (ej. up/down)"),
    include_false_positives: bool = Query(
        default=False,
        description="Incluye hallazgos marcados como falso positivo (HU-022). Excluidos por defecto.",
    ),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    queue: JobQueue = Depends(get_job_queue),
    fp_store: FalsePositiveStore = Depends(get_false_positive_store),
) -> ScanDetailResponse:
    """Consulta progreso, activos descubiertos y hallazgos paginados de un escaneo.

    Coherente en cualquier estado del ciclo de vida: mientras el escaneo
    está `pending`/`running` (o si terminó en `failed`), `assets` y
    `findings` se devuelven vacíos en lugar de fallar, ya que el `Job`
    aún no tiene `result`.
    """
    job = queue.get_job(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Escaneo {scan_id} no encontrado")

    assets: list[HostFinding] = []
    all_findings: list[VulnFinding] = []
    if job.result is not None:
        if job.job_type == JobType.DISCOVERY:
            assets = [HostFinding(**host) for host in job.result.get("hosts", [])]
        else:
            all_findings = [VulnFinding(**finding) for finding in job.result.get("findings", [])]

    if asset_status is not None:
        assets = [asset for asset in assets if asset.status == asset_status]

    if severity is not None:
        all_findings = [finding for finding in all_findings if finding.severity == severity]

    if not include_false_positives and all_findings:
        marks = await fp_store.list_marks(scan_id=str(scan_id))
        marked_keys = {(mark.finding_id, mark.matched_at) for mark in marks}
        all_findings = [
            finding for finding in all_findings if (finding.template_id, finding.matched_at) not in marked_keys
        ]

    total = len(all_findings)
    start = (page - 1) * page_size
    page_items = all_findings[start : start + page_size]

    return ScanDetailResponse(
        scan_id=job.id,
        scan_type=job.job_type,
        status=job.status,
        progress=_PROGRESS_BY_STATUS[job.status],
        target=job.params.get("target", ""),
        assets=assets,
        findings=PaginatedFindings(
            items=page_items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=ceil(total / page_size),
        ),
        error=job.error,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
    )


@router.post(
    "/{scan_id}/findings/false-positive",
    status_code=201,
    response_model=FalsePositiveMarkResponse,
)
async def mark_finding_false_positive(
    scan_id: UUID,
    body: MarkFalsePositiveRequest,
    request: Request,
    fp_store: FalsePositiveStore = Depends(get_false_positive_store),
    x_atrox_user: str | None = Header(default=None, alias="X-Atrox-User"),
) -> FalsePositiveMarkResponse:
    """Marca un hallazgo como falso positivo (HU-022): persiste usuario y
    timestamp, y lo excluye de `GET /api/scans/{scan_id}` por defecto.
    """
    finding_id = body.finding_id or body.finding.template_id
    user = x_atrox_user or "system"

    mark = await fp_store.mark(
        scan_id=str(scan_id),
        finding_id=finding_id,
        finding=body.finding,
        user=user,
        reason=body.reason,
    )

    audit_log = getattr(request.app.state, "audit_log", None)
    if audit_log is not None:
        await audit_log.record(
            user=user,
            action="finding.marked_false_positive",
            resource=f"scan:{scan_id}:finding:{finding_id}",
            metadata={"reason": body.reason} if body.reason else {},
        )

    return FalsePositiveMarkResponse(
        id=mark.id,
        scan_id=mark.scan_id,
        finding_id=mark.finding_id,
        user=mark.user,
        reason=mark.reason,
        marked_at=mark.marked_at,
    )


@router.get("/{scan_id}/findings/false-positives", response_model=list[FalsePositiveMark])
async def list_false_positives(
    scan_id: UUID,
    fp_store: FalsePositiveStore = Depends(get_false_positive_store),
) -> list[FalsePositiveMark]:
    """Lista los hallazgos marcados como falso positivo de un escaneo — dataset
    etiquetado reutilizable para reentrenamiento/heurística futura (HU-022 DoD).
    """
    return await fp_store.list_marks(scan_id=str(scan_id))
