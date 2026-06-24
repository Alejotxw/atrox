import asyncio
import shutil

import pytest

from atrox.scanner.models import ScanStatus
from atrox.scanner.nmap_wrapper import NmapWrapper


@pytest.mark.integration
def test_integration_scan_lab_target_scanme() -> None:
    if shutil.which("nmap") is None:
        pytest.skip("Nmap no instalado — omitiendo prueba de integración de laboratorio")

    wrapper = NmapWrapper(timeout_seconds=120)

    result = asyncio.run(wrapper.scan("scanme.nmap.org", "22,80"))

    assert result.status in {ScanStatus.COMPLETED, ScanStatus.UNREACHABLE}
    assert result.target == "scanme.nmap.org"
    assert result.error is None or result.status != ScanStatus.COMPLETED

    if result.status == ScanStatus.COMPLETED:
        assert len(result.hosts) >= 1
        open_ports = [port for host in result.hosts for port in host.ports]
        assert all(port.protocol for port in open_ports)
        assert all(port.port > 0 for port in open_ports)
