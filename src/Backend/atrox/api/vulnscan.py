from fastapi import APIRouter, Depends, Request

from atrox.config import Settings, get_settings
from atrox.scanner.models import VulnScanRequest, VulnScanResult
from atrox.scanner.nuclei_wrapper import NucleiWrapper

router = APIRouter(prefix="/api/vulnscan", tags=["vulnscan"])


def get_nuclei_wrapper(settings: Settings = Depends(get_settings)) -> NucleiWrapper:
    return NucleiWrapper(
        nuclei_path=settings.nuclei_path,
        timeout_seconds=settings.nuclei_timeout_seconds,
        sandbox_templates=settings.nuclei_sandbox_templates,
    )


@router.post("/scan", response_model=VulnScanResult)
async def run_vuln_scan(
    request_body: VulnScanRequest,
    request: Request,
    scanner: NucleiWrapper = Depends(get_nuclei_wrapper),
) -> VulnScanResult:
    """Ejecuta Nuclei y, si el cifrado está activo, persiste hallazgos cifrados."""
    result = await scanner.scan(
        target=request_body.target,
        templates=request_body.templates or None,
        severities=request_body.severities or None,
        tags=request_body.tags or None,
    )

    persistence = getattr(request.app.state, "persistence", None)
    if persistence is not None and result.findings:
        await persistence.save_findings_from_vulnscan(result.findings)

    return result
