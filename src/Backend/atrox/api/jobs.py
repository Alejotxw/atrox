"""Router de trabajos de escaneo — CRUD y metricas (HU-004 / HU-007)."""

from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from atrox.queue.models import Job, JobType, QueueMetrics
from atrox.queue.service import JobQueue, QueueFullError
from atrox.scanner.validators import validate_target

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


class JobSubmitRequest(BaseModel):
    """Payload para crear un nuevo trabajo de escaneo."""

    type: JobType
    target: str
    params: dict = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def check_target(cls, value: str) -> str:
        return validate_target(value)


class JobSubmitResponse(BaseModel):
    """Respuesta al crear un trabajo de escaneo."""

    job_id: UUID
    status: str


def get_job_queue(request: Request) -> JobQueue:
    """Obtiene la instancia de JobQueue desde app.state."""
    return request.app.state.job_queue


@router.post("", status_code=202, response_model=JobSubmitResponse)
async def submit_job(
    body: JobSubmitRequest,
    request: Request,
    queue: JobQueue = Depends(get_job_queue),
    x_atrox_user: str | None = Header(default=None, alias="X-Atrox-User"),
) -> JobSubmitResponse:
    """Envia un trabajo de escaneo a la cola. Retorna 202 Accepted."""
    try:
        job = await queue.submit(
            job_type=body.type,
            params={"target": body.target, **body.params},
        )
    except QueueFullError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    audit_log = getattr(request.app.state, "audit_log", None)
    if audit_log is not None:
        await audit_log.record(
            user=x_atrox_user or "system",
            action="scan.submitted",
            resource=f"job:{job.id}",
            metadata={"type": body.type.value, "target": body.target},
        )

    return JobSubmitResponse(job_id=job.id, status=job.status.value)


@router.get("", response_model=list[Job])
async def list_jobs(
    request: Request,
    queue: JobQueue = Depends(get_job_queue),
) -> list[Job]:
    """Retorna todos los trabajos; descifra findings del result si hay cifrado."""
    persistence = getattr(request.app.state, "persistence", None)
    jobs = queue.list_jobs()
    if persistence is None:
        return jobs

    decrypted: list[Job] = []
    for job in jobs:
        if job.result and isinstance(job.result.get("findings"), list):
            data = job.model_dump(mode="json")
            data["result"] = persistence.decrypt_job_result(job.result)
            decrypted.append(Job.model_validate(data))
        else:
            decrypted.append(job)
    return decrypted


@router.get("/metrics", response_model=QueueMetrics)
async def get_metrics(
    queue: JobQueue = Depends(get_job_queue),
) -> QueueMetrics:
    """Retorna metricas agregadas de la cola de trabajos."""
    return queue.metrics


@router.get("/{job_id}", response_model=Job)
async def get_job(
    job_id: UUID,
    request: Request,
    queue: JobQueue = Depends(get_job_queue),
) -> Job:
    """Consulta el estado y resultado de un trabajo por su ID."""
    job = queue.get_job(job_id)
    if job is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trabajo {job_id} no encontrado",
        )

    persistence = getattr(request.app.state, "persistence", None)
    if persistence is not None and job.result and isinstance(job.result.get("findings"), list):
        data = job.model_dump(mode="json")
        data["result"] = persistence.decrypt_job_result(job.result)
        return Job.model_validate(data)

    return job
