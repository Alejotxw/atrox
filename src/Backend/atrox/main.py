import asyncio
from concurrent.futures import ProcessPoolExecutor
from contextlib import asynccontextmanager
import logging
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from atrox.api.audit import router as audit_router
from atrox.api.auth import router as auth_router
from atrox.api.chat import router as chat_router
from atrox.api.console import router as console_router
from atrox.api.credentials import router as credentials_router
from atrox.api.discovery import router as discovery_router
from atrox.api.findings import router as findings_router
from atrox.api.health import router as health_router
from atrox.api.jobs import router as jobs_router
from atrox.api.payloads import router as payloads_router
from atrox.api.reports import router as reports_router
from atrox.api.scans import router as scans_router
from atrox.api.scoring import router as scoring_router
from atrox.api.threats import router as threats_router
from atrox.api.validate import router as validate_router
from atrox.api.vectors import router as vectors_router
from atrox.api.vulnscan import router as vulnscan_router
from atrox.ai.schemas.rejections import build_rejection_logger
from atrox.config import get_settings
from atrox.console.bus import get_scan_log_bus
from atrox.console.models import LogSeverity
from atrox.findings.store import FalsePositiveStore
from atrox.persistence.deps import build_persistence_service
from atrox.queue.models import Job, JobType
from atrox.queue.service import JobQueue
from atrox.scanner.models import ScanStatus, VulnSeverity
from atrox.scanner.nmap_wrapper import NmapWrapper
from atrox.scanner.nuclei_wrapper import NucleiWrapper
from atrox.security.audit_deps import build_audit_log_service
from atrox.security.auth_deps import require_mfa_admin
from atrox.security.deps import get_encryption_service_from_settings
from atrox.security.encryption import EncryptionKeyError
from atrox.security.mfa_service import MfaService
from atrox.security.sensitive_fields import SensitiveFieldEncryptor
from atrox.threat_intel.service import build_nvd_sync_service

logger = logging.getLogger(__name__)

# Referencia al servicio de persistencia cifrada para el dispatcher de jobs
_persistence = None


# Estados en los que el wrapper nunca llegó a completar un escaneo real
# (binario no encontrado, timeout, error inesperado) — deben fallar el job,
# no devolver un resultado "exitoso" vacío indistinguible de "0 hallazgos".
_TOOL_FAILURE_STATUSES = (ScanStatus.ERROR, ScanStatus.TIMEOUT)


def _raise_if_tool_failed(result) -> None:
    if result.status in _TOOL_FAILURE_STATUSES:
        raise RuntimeError(result.error or f"El escaneo terminó en estado {result.status.value}")


async def _emit_command(module: str, job_id, command_args: list[str]) -> None:
    """Muestra el comando real de la herramienta en la consola antes de ejecutarlo."""
    await get_scan_log_bus().emit(
        module,
        f"$ {' '.join(command_args)}",
        severity=LogSeverity.INFO,
        job_id=job_id,
    )


async def _dispatch_scan(job: Job) -> dict:
    """Dispatcher que selecciona el wrapper segun el tipo de escaneo."""
    settings = get_settings()

    if job.job_type == JobType.DISCOVERY:
        wrapper = NmapWrapper(
            nmap_path=settings.nmap_path,
            timeout_seconds=settings.nmap_timeout_seconds,
            on_command=lambda args: _emit_command("NMAP", job.id, args),
        )
        result = await wrapper.scan(
            target=job.params["target"],
            port_range=job.params.get("port_range", "1-1024"),
        )
        _raise_if_tool_failed(result)

        hosts_up = [host for host in result.hosts if host.status == "up"]
        port_count = sum(len(host.ports) for host in hosts_up)
        await get_scan_log_bus().emit(
            "NMAP",
            f"{len(hosts_up)} host(s) activo(s), {port_count} puerto(s) abiertos",
            severity=LogSeverity.INFO,
            job_id=job.id,
        )

        return result.model_dump()

    # JobType.VULNSCAN
    wrapper_nuclei = NucleiWrapper(
        nuclei_path=settings.nuclei_path,
        timeout_seconds=settings.nuclei_timeout_seconds,
        on_command=lambda args: _emit_command("NUCLEI", job.id, args),
        docker_image=settings.nuclei_docker_image,
        docker_templates_volume=settings.nuclei_docker_templates_volume,
    )
    severity_param = job.params.get("severity") or job.params.get("severities")
    if isinstance(severity_param, str):
        severities = [s.strip() for s in severity_param.split(",") if s.strip()]
    else:
        severities = severity_param

    result = await wrapper_nuclei.scan(
        target=job.params["target"],
        templates=job.params.get("templates"),
        severities=severities,
        tags=job.params.get("tags"),
    )
    _raise_if_tool_failed(result)

    for finding in result.findings:
        if finding.severity not in (VulnSeverity.CRITICAL, VulnSeverity.HIGH):
            continue
        log_severity = (
            LogSeverity.CRITICAL
            if finding.severity == VulnSeverity.CRITICAL
            else LogSeverity.WARNING
        )
        await get_scan_log_bus().emit(
            "NUCLEI",
            f"[{finding.severity.value.upper()}] {finding.name} en {finding.host}",
            severity=log_severity,
            job_id=job.id,
        )

    payload = result.model_dump()

    # Persistir hallazgos cifrados y dejar el result del job también cifrado
    if _persistence is not None and payload.get("findings"):
        try:
            await _persistence.save_findings_from_vulnscan(
                result.findings,
                job_id=job.id,
            )
            payload = _persistence.encrypt_job_result(payload)
        except Exception:
            logger.exception(
                "No se pudieron cifrar/persistir hallazgos del job %s",
                job.id,
            )

    return payload


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _persistence
    settings = get_settings()

    # Servicio MFA (HU-018)
    mfa_service = MfaService(
        admin_username=settings.admin_username,
        admin_password=settings.admin_password,
        totp_secret=settings.totp_secret,
        session_ttl_minutes=settings.session_ttl_minutes,
        max_failed_attempts=settings.mfa_max_failed_attempts,
        lockout_minutes=settings.mfa_lockout_minutes,
    )
    app.state.mfa_service = mfa_service

    job_queue = JobQueue(
        max_concurrent=settings.max_concurrent_scans,
        max_queue_size=settings.queue_max_size,
    )
    app.state.job_queue = job_queue
    app.state.scan_log_bus = get_scan_log_bus()

    executor = ProcessPoolExecutor(max_workers=settings.parse_workers)
    await job_queue.start(scanner=_dispatch_scan, executor=executor)

    app.state.audit_log = None
    if settings.audit_signing_key:
        audit_log = build_audit_log_service()
        await audit_log.purge_expired()
        app.state.audit_log = audit_log

    # Log de rechazos de respuestas IA (HU-017): en memoria por defecto;
    # persiste a JSONL solo si ATROX_LLM_REJECTION_LOG_PATH está configurado.
    app.state.llm_rejections = build_rejection_logger(settings.llm_rejection_log_path)

    # Persistencia cifrada (HU-007)
    app.state.persistence = None
    _persistence = None
    if settings.encryption_master_key:
        try:
            persistence = build_persistence_service()
            app.state.persistence = persistence
            _persistence = persistence
        except EncryptionKeyError:
            logger.warning("Cifrado no inicializado: llave inválida o ausente")

    # Store de falsos positivos (HU-022), opcionalmente con cifrado
    fp_encryptor = None
    if settings.encryption_master_key:
        try:
            fp_encryptor = SensitiveFieldEncryptor(get_encryption_service_from_settings())
        except EncryptionKeyError:
            logger.warning("Encryptor de falsos positivos no inicializado")
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
    _persistence = None


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
    application.include_router(auth_router)
    application.include_router(discovery_router)
    application.include_router(vulnscan_router)
    application.include_router(jobs_router)
    application.include_router(console_router)
    application.include_router(scans_router)
    application.include_router(audit_router, dependencies=[Depends(require_mfa_admin)])
    application.include_router(vectors_router)
    application.include_router(chat_router)
    application.include_router(payloads_router)
    application.include_router(scoring_router)
    application.include_router(validate_router)
    application.include_router(threats_router)
    application.include_router(findings_router)
    application.include_router(credentials_router)
    application.include_router(reports_router)
    return application


app = create_app()
