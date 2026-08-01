"""API tests for POST /api/vulnscan/scan — Strict TDD."""

import pytest
from fastapi.testclient import TestClient

from atrox.api.vulnscan import get_nuclei_wrapper
from atrox.main import app
from atrox.scanner.models import ScanStatus, VulnScanResult
from atrox.scanner.nuclei_wrapper import NucleiWrapper
from tests.fixtures.nuclei_samples import SAMPLE_NUCLEI_JSONL_MULTI


class MockNucleiWrapper(NucleiWrapper):
    def __init__(self) -> None:
        super().__init__(runner=self._mock_runner)

    async def _mock_runner(self, _args: list[str]) -> tuple[int, str, str]:
        return 0, SAMPLE_NUCLEI_JSONL_MULTI, ""


@pytest.fixture
def client() -> TestClient:
    app.dependency_overrides[get_nuclei_wrapper] = lambda: MockNucleiWrapper()
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_vulnscan_endpoint_returns_completed_json(client: TestClient) -> None:
    response = client.post(
        "/api/vulnscan/scan",
        json={"target": "192.168.1.10"},
    )

    assert response.status_code == 200
    body = response.json()

    assert body["status"] == "completed"
    assert body["target"] == "192.168.1.10"
    assert len(body["findings"]) == 2
    assert body["findings"][0]["template_id"] == "cve-2021-41773"
    assert body["findings"][0]["severity"] == "critical"
    assert body["findings"][1]["template_id"] == "cve-2023-22515"


def test_vulnscan_rejects_invalid_target(client: TestClient) -> None:
    response = client.post(
        "/api/vulnscan/scan",
        json={"target": "not a valid target!!!"},
    )

    assert response.status_code == 422


def test_vulnscan_accepts_fqdn_target(client: TestClient) -> None:
    response = client.post(
        "/api/vulnscan/scan",
        json={"target": "scanme.nmap.org"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"


def test_vulnscan_response_conforms_to_schema(client: TestClient) -> None:
    response = client.post(
        "/api/vulnscan/scan",
        json={"target": "192.168.1.10"},
    )

    body = response.json()

    result = VulnScanResult(**body)
    assert result.status == ScanStatus.COMPLETED
    assert len(result.findings) == 2
    assert result.error is None


def test_vulnscan_accepts_optional_filters(client: TestClient) -> None:
    response = client.post(
        "/api/vulnscan/scan",
        json={
            "target": "192.168.1.10",
            "templates": [],
            "severities": ["critical"],
            "tags": ["cve"],
        },
    )

    assert response.status_code == 200


def test_vulnscan_error_response_structure() -> None:
    async def error_runner(_args: list[str]) -> tuple[int, str, str]:
        raise FileNotFoundError("nuclei not found")

    app.dependency_overrides[get_nuclei_wrapper] = lambda: NucleiWrapper(runner=error_runner)
    client = TestClient(app)

    response = client.post(
        "/api/vulnscan/scan",
        json={"target": "192.168.1.10"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "error"
    assert body["error"] is not None
    assert "Nuclei no encontrado" in body["error"]
