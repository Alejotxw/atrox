import asyncio
from concurrent.futures import ProcessPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from atrox.api.audit import router as audit_router
from atrox.api.discovery import router as discovery_router
from atrox.api.health import router as health_router
from atrox.api.jobs import router as jobs_router
from atrox.api.payloads import router as payloads_router
from atrox.api.scans import router as scans_router
from atrox.api.scoring import router as scoring_router
from atrox.api.threats import router as threats_router
from atrox.api.vectors import router as vectors_router
from atrox.api.vulnscan import router as vulnscan_router
from atrox.config import get_settings
from atrox.findings.store import FalsePositiveStore
from atrox.queue.models import Job, JobType
from atrox.queue.service import JobQueue
from atrox.scanner.nmap_wrapper import NmapWrapper
from atrox.scanner.nuclei_wrapper import NucleiWrapper
from atrox.security.audit_deps import build_audit_log_service
from atrox.security.deps import get_encryption_service_from_settings
from atrox.security.sensitive_fields import SensitiveFieldEncryptor
from atrox.threat_intel.service import build_nvd_sync_service


async def _dispatch_scan(job: Job) -> dict:
    """Dispatcher que selecciona el wrapper segun el tipo de escaneo."""
    settings = get_settings()

    if job.job_type == JobType.DISCOVERY:
        wrapper = NmapWrapper(
            nmap_path=settings.nmap_path,
            timeout_seconds=settings.nmap_timeout_seconds,
        )
        result = await wrapper.scan(
            target=job.params["target"],
            port_range=job.params.get("port_range", "1-1024"),
        )
        return result.model_dump()

    # JobType.VULNSCAN
    wrapper_nuclei = NucleiWrapper(
        nuclei_path=settings.nuclei_path,
        timeout_seconds=settings.nuclei_timeout_seconds,
    )
    result = await wrapper_nuclei.scan(
        target=job.params["target"],
        templates=job.params.get("templates"),
        severities=job.params.get("severities"),
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

    app.state.audit_log = None
    if settings.audit_signing_key:
        audit_log = build_audit_log_service()
        await audit_log.purge_expired()
        app.state.audit_log = audit_log

    fp_encryptor = None
    if settings.encryption_master_key:
        fp_encryptor = SensitiveFieldEncryptor(get_encryption_service_from_settings())
    app.state.false_positive_store = FalsePositiveStore(
        store_path=Path(settings.false_positive_store_path),
        encryptor=fp_encryptor,
    )

    # Sincronización diaria NVD (HU-005 / RF-010): el scheduler duerme
    # primero, así el arranque no hace llamadas de red; la primera
    # sincronización se dispara manualmente (POST /api/threats/sync o CLI).
    nvd_sync_service = build_nvd_sync_service()
    app.state.nvd_sync_service = nvd_sync_service
    app.state.nvd_sync_task = None
    app.state.nvd_startup_sync_task = None
    if settings.nvd_sync_enabled:
        app.state.nvd_sync_task = asyncio.create_task(
            nvd_sync_service.run_daily(
                interval_seconds=settings.nvd_sync_interval_hours * 3600
            )
        )
        if settings.nvd_sync_on_startup:
            app.state.nvd_startup_sync_task = asyncio.create_task(
                nvd_sync_service.sync_once_safe()
            )

    yield

    for attr in ("nvd_sync_task", "nvd_startup_sync_task"):
        task = getattr(app.state, attr, None)
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    await job_queue.shutdown()


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.include_router(health_router)
    application.include_router(discovery_router)
    application.include_router(vulnscan_router)
    application.include_router(jobs_router)
    application.include_router(scans_router)
    application.include_router(audit_router)
    application.include_router(vectors_router)
    application.include_router(payloads_router)
    application.include_router(scoring_router)
    application.include_router(threats_router)
    return application


app = create_app()
