from concurrent.futures import ProcessPoolExecutor
from contextlib import asynccontextmanager

from fastapi import FastAPI

from atrox.api.discovery import router as discovery_router
from atrox.api.health import router as health_router
from atrox.api.jobs import router as jobs_router
from atrox.api.vulnscan import router as vulnscan_router
from atrox.config import get_settings
from atrox.queue.models import Job, JobType
from atrox.queue.service import JobQueue
from atrox.scanner.nmap_wrapper import NmapWrapper
from atrox.scanner.nuclei_wrapper import NucleiWrapper


async def _dispatch_scan(job: Job) -> dict:
    """Dispatcher que selecciona el wrapper segun el tipo de escaneo."""
    settings = get_settings()

    if job.job_type == JobType.DISCOVERY:
        wrapper = NmapWrapper(
            nmap_path=settings.nmap_path,
            timeout=settings.nmap_timeout_seconds,
        )
        result = await wrapper.scan(
            target=job.params["target"],
            port_range=job.params.get("port_range"),
        )
        return result.model_dump()

    # JobType.VULNSCAN
    wrapper_nuclei = NucleiWrapper(
        nuclei_path=settings.nuclei_path,
        timeout=settings.nuclei_timeout_seconds,
    )
    result = await wrapper_nuclei.scan(
        target=job.params["target"],
        templates=job.params.get("templates"),
        severity=job.params.get("severity"),
    )
    return result.model_dump()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    job_queue = JobQueue(
        max_concurrent=settings.max_concurrent_scans,
        max_queue_size=settings.queue_max_size,
    )
    app.state.job_queue = job_queue

    executor = ProcessPoolExecutor(max_workers=settings.parse_workers)
    await job_queue.start(scanner=_dispatch_scan, executor=executor)

    yield

    await job_queue.shutdown()


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
    )
    application.include_router(health_router)
    application.include_router(discovery_router)
    application.include_router(vulnscan_router)
    application.include_router(jobs_router)
    return application


app = create_app()
