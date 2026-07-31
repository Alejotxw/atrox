"""Router REST unificado de creación de escaneos (HU-009).

Fachada pública sobre la cola de trabajos de HU-004: valida el payload
(objetivo + tipo de escaneo) y delega en `JobQueue.submit`, exponiendo el
identificador resultante como `scan_id`. Como `scan_id` es el mismo UUID
del `Job` subyacente, el estado también puede consultarse vía
`GET /api/jobs/{scan_id}` (HU-004) sin necesidad de duplicar ese endpoint.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from atrox.api.jobs import get_job_queue
from atrox.queue.models import JobType
from atrox.queue.service import JobQueue, QueueFullError
from atrox.scanner.validators import validate_target

router = APIRouter(prefix="/api/scans", tags=["scans"])


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
