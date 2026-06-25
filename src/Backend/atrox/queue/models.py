"""Modelos de dominio para la cola de trabajos de escaneo."""

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    """Estado del ciclo de vida de un trabajo de escaneo."""

    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class JobType(str, Enum):
    """Tipo de escaneo que ejecuta el trabajo."""

    DISCOVERY = "discovery"
    VULNSCAN = "vulnscan"


class Job(BaseModel):
    """Representacion de un trabajo de escaneo en la cola."""

    id: UUID = Field(default_factory=uuid4)
    job_type: JobType
    status: JobStatus = JobStatus.PENDING
    params: dict
    result: dict | None = None
    error: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    finished_at: datetime | None = None

    # Transiciones validas del ciclo de vida del trabajo
    _VALID_TRANSITIONS: dict[JobStatus, set[JobStatus]] = {
        JobStatus.PENDING: {JobStatus.RUNNING},
        JobStatus.RUNNING: {JobStatus.DONE, JobStatus.FAILED},
        JobStatus.DONE: set(),
        JobStatus.FAILED: set(),
    }

    def transition_to(self, new_status: JobStatus) -> None:
        """Transiciona el trabajo a un nuevo estado validando la transicion.

        Raises:
            ValueError: Si la transicion no es valida segun el ciclo de vida.
        """
        allowed = self._VALID_TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            raise ValueError(
                f"Transicion invalida: {self.status.value} -> {new_status.value}"
            )
        self.status = new_status


class QueueMetrics(BaseModel):
    """Metricas agregadas de la cola de trabajos."""

    queue_depth: int
    active_jobs: int
    completed_count: int
    failed_count: int
    avg_duration_seconds: float
