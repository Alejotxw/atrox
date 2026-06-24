"""Integration tests for NucleiWrapper — requires Nuclei installed."""

import asyncio
import shutil

import pytest

from atrox.scanner.models import ScanStatus
from atrox.scanner.nuclei_wrapper import NucleiWrapper


@pytest.mark.integration
def test_integration_scan_with_real_nuclei() -> None:
    if shutil.which("nuclei") is None:
        pytest.skip("Nuclei no instalado — omitiendo prueba de integracion")

    wrapper = NucleiWrapper(timeout_seconds=120)

    result = asyncio.run(wrapper.scan("scanme.nmap.org"))

    assert result.status in {ScanStatus.COMPLETED, ScanStatus.TIMEOUT}
    assert result.target == "scanme.nmap.org"

    if result.status == ScanStatus.COMPLETED:
        for finding in result.findings:
            assert finding.template_id
            assert finding.name
            assert finding.severity is not None
            assert finding.host
            assert finding.matched_at
