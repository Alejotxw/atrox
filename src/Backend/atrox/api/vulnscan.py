from fastapi import APIRouter, Depends

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
    request: VulnScanRequest,
    scanner: NucleiWrapper = Depends(get_nuclei_wrapper),
) -> VulnScanResult:
    return await scanner.scan(
        target=request.target,
        templates=request.templates or None,
        severities=request.severities or None,
        tags=request.tags or None,
    )
