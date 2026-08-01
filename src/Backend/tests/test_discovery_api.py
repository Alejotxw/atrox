import pytest
from fastapi.testclient import TestClient

from atrox.api.discovery import get_nmap_wrapper
from atrox.main import app
from atrox.scanner.nmap_wrapper import NmapWrapper
from tests.fixtures.nmap_samples import SAMPLE_NMAP_XML_UP


class MockNmapWrapper(NmapWrapper):
    def __init__(self) -> None:
        super().__init__(runner=self._mock_runner)

    async def _mock_runner(self, _args: list[str]) -> tuple[int, str, str]:
        return 0, SAMPLE_NMAP_XML_UP, ""


@pytest.fixture
def client() -> TestClient:
    app.dependency_overrides[get_nmap_wrapper] = lambda: MockNmapWrapper()
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_discovery_scan_endpoint_returns_json(client: TestClient) -> None:
    response = client.post(
        "/api/discovery/scan",
        json={"target": "192.168.1.10", "port_range": "22,80"},
    )

    assert response.status_code == 200
    body = response.json()

    assert body["status"] == "completed"
    assert body["target"] == "192.168.1.10"
    assert body["port_range"] == "22,80"
    assert len(body["hosts"]) == 1
    assert body["hosts"][0]["ports"][0]["port"] == 22
    assert body["hosts"][0]["ports"][0]["protocol"] == "tcp"
    assert body["hosts"][0]["ports"][0]["service"] == "ssh"
    assert "OpenSSH" in body["hosts"][0]["ports"][0]["version"]


def test_discovery_scan_rejects_invalid_target(client: TestClient) -> None:
    response = client.post(
        "/api/discovery/scan",
        json={"target": "%%%invalid%%%", "port_range": "80"},
    )

    assert response.status_code == 422


def test_discovery_scan_rejects_invalid_port_range(client: TestClient) -> None:
    response = client.post(
        "/api/discovery/scan",
        json={"target": "192.168.1.1", "port_range": "99999"},
    )

    assert response.status_code == 422


def test_discovery_scan_accepts_fqdn(client: TestClient) -> None:
    response = client.post(
        "/api/discovery/scan",
        json={"target": "scanme.nmap.org", "port_range": "22"},
    )

    assert response.status_code == 200


def test_unreachable_target_returns_graceful_response() -> None:
    async def unreachable_runner(_args: list[str]) -> tuple[int, str, str]:
        return 0, """<?xml version="1.0"?><nmaprun><host><status state="down"/><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>""", ""

    app.dependency_overrides[get_nmap_wrapper] = lambda: NmapWrapper(runner=unreachable_runner)
    client = TestClient(app)

    response = client.post(
        "/api/discovery/scan",
        json={"target": "10.0.0.1", "port_range": "22"},
    )

    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["status"] == "unreachable"
