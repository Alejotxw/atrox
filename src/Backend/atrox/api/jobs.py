"""Router de trabajos de escaneo — CRUD y metricas (HU-004)."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from atrox.queue.models import Job, JobType, QueueMetrics
from atrox.queue.service import JobQueue, QueueFullError
from atrox.scanner.validators import validate_target

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


# -- Modelos de request/response para la API --------------------------------


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


# -- Dependencia de inyeccion -----------------------------------------------


def get_job_queue(request: Request) -> JobQueue:
    """Obtiene la instancia de JobQueue desde app.state."""
    return request.app.state.job_queue


# -- Endpoints ---------------------------------------------------------------
# NOTA: /metrics y la lista GET "" se registran ANTES de /{job_id}
# para que FastAPI no interprete "metrics" como un UUID.


@router.post("", status_code=202, response_model=JobSubmitResponse)
async def submit_job(
    body: JobSubmitRequest,
    queue: JobQueue = Depends(get_job_queue),
) -> JobSubmitResponse:
    """Envia un trabajo de escaneo a la cola. Retorna 202 Accepted."""
    try:
        job = await queue.submit(
            job_type=body.type,
            params={"target": body.target, **body.params},
        )
    except QueueFullError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return JobSubmitResponse(job_id=job.id, status=job.status.value)


@router.get("", response_model=list[Job])
async def list_jobs(
    queue: JobQueue = Depends(get_job_queue),
) -> list[Job]:
    """Retorna todos los trabajos registrados."""
    return queue.list_jobs()


@router.get("/metrics", response_model=QueueMetrics)
async def get_metrics(
    queue: JobQueue = Depends(get_job_queue),
) -> QueueMetrics:
    """Retorna metricas agregadas de la cola de trabajos."""
    return queue.metrics


@router.get("/{job_id}", response_model=Job)
async def get_job(
    job_id: UUID,
    queue: JobQueue = Depends(get_job_queue),
) -> Job:
    """Consulta el estado y resultado de un trabajo por su ID."""
    job = queue.get_job(job_id)
    if job is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trabajo {job_id} no encontrado",
        )
    return job
