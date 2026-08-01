"""Servicio de cola de trabajos de escaneo concurrente."""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from concurrent.futures import Executor
from datetime import datetime, timezone
from uuid import UUID

from atrox.queue.models import Job, JobStatus, JobType, QueueMetrics

logger = logging.getLogger(__name__)

# Tipo del callable que ejecuta el escaneo dado un Job
ScannerCallable = Callable[[Job], Awaitable[dict]]


class QueueFullError(Exception):
    """Error lanzado cuando la cola alcanza su capacidad maxima."""


class JobQueue:
    """Cola de trabajos con control de concurrencia via semaforo."""

    def __init__(
        self,
        max_concurrent: int = 10,
        max_queue_size: int = 50,
    ) -> None:
        self._max_concurrent = max_concurrent
        self._max_queue_size = max_queue_size
        self._queue: asyncio.Queue[UUID] = asyncio.Queue(maxsize=max_queue_size)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._jobs: dict[UUID, Job] = {}
        self._workers: list[asyncio.Task] = []
        self._scanner: ScannerCallable | None = None
        self._executor: Executor | None = None

    async def submit(self, job_type: JobType, params: dict) -> Job:
        """Crea un trabajo y lo encola para ejecucion."""
        if self._queue.full():
            raise QueueFullError(
                f"Cola llena: maximo {self._max_queue_size} trabajos en espera"
            )

        job = Job(job_type=job_type, params=params)
        self._jobs[job.id] = job
        await self._queue.put(job.id)
        return job

    def get_job(self, job_id: UUID) -> Job | None:
        """Retorna un trabajo por su ID, o None si no existe."""
        return self._jobs.get(job_id)

    def list_jobs(self) -> list[Job]:
        """Retorna todos los trabajos registrados."""
        return list(self._jobs.values())

    @property
    def metrics(self) -> QueueMetrics:
        """Calcula metricas agregadas del estado actual de la cola."""
        jobs = self._jobs.values()
        pending = sum(1 for j in jobs if j.status == JobStatus.PENDING)
        running = sum(1 for j in jobs if j.status == JobStatus.RUNNING)
        done = sum(1 for j in jobs if j.status == JobStatus.DONE)
        failed = sum(1 for j in jobs if j.status == JobStatus.FAILED)

        durations = [
            (j.finished_at - j.started_at).total_seconds()
            for j in jobs
            if j.status == JobStatus.DONE
            and j.started_at is not None
            and j.finished_at is not None
        ]
        avg_duration = sum(durations) / len(durations) if durations else 0.0

        return QueueMetrics(
            queue_depth=pending,
            active_jobs=running,
            completed_count=done,
            failed_count=failed,
            avg_duration_seconds=avg_duration,
        )

    async def start(
        self,
        scanner: ScannerCallable,
        executor: Executor | None = None,
    ) -> None:
        """Inicia los workers de la cola.

        Args:
            scanner: Callable asincrono que ejecuta el escaneo.
            executor: Executor opcional para delegar parseo CPU-bound.
        """
        self._scanner = scanner
        self._executor = executor
        for _ in range(self._max_concurrent):
            task = asyncio.create_task(self._worker())
            self._workers.append(task)

    async def shutdown(self) -> None:
        """Cancela todos los workers y espera a que finalicen."""
        for worker in self._workers:
            worker.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        if self._executor is not None:
            self._executor.shutdown(wait=False)
            self._executor = None

    async def _worker(self) -> None:
        """Corrutina worker: consume trabajos de la cola y los ejecuta."""
        while True:
            try:
                job_id = await self._queue.get()
            except asyncio.CancelledError:
                return

            job = self._jobs.get(job_id)
            if job is None:
                self._queue.task_done()
                continue

            async with self._semaphore:
                job.transition_to(JobStatus.RUNNING)
                job.started_at = datetime.now(timezone.utc)

                try:
                    result = await self._scanner(job)  # type: ignore[misc]
                    job.result = result
                    job.transition_to(JobStatus.DONE)
                except Exception as exc:
                    job.error = str(exc)
                    job.transition_to(JobStatus.FAILED)
                    logger.exception("Error ejecutando trabajo %s", job_id)
                finally:
                    job.finished_at = datetime.now(timezone.utc)

            self._queue.task_done()
