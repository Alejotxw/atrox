from fastapi import APIRouter, Depends

from atrox.config import Settings, get_settings
from atrox.scanner.models import DiscoveryScanRequest, DiscoveryScanResult
from atrox.scanner.nmap_wrapper import NmapWrapper

router = APIRouter(prefix="/api/discovery", tags=["discovery"])


def get_nmap_wrapper(settings: Settings = Depends(get_settings)) -> NmapWrapper:
    return NmapWrapper(
        nmap_path=settings.nmap_path,
        timeout_seconds=settings.nmap_timeout_seconds,
    )


@router.post("/scan", response_model=DiscoveryScanResult)
async def run_discovery_scan(
    request: DiscoveryScanRequest,
    scanner: NmapWrapper = Depends(get_nmap_wrapper),
) -> DiscoveryScanResult:
    return await scanner.scan(
        target=request.target,
        port_range=request.port_range,
    )
