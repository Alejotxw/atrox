"""Tests unitarios para GET /api/scans/{id} — detalle de escaneo (HU-010).

Convenciones de filtrado (confirmadas con el usuario):
- `severity` filtra la lista de hallazgos (VulnFinding no tiene campo de
  estado propio, así que el filtro de "estado" del AC se interpreta sobre
  los activos descubiertos).
- `asset_status` filtra los activos descubiertos por HostFinding.status
  ("up"/"down"), ya provisto por el wrapper de Nmap.
"""

import time
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from atrox.api.jobs import get_job_queue
from atrox.main import app
from atrox.queue.models import JobStatus, JobType
from atrox.queue.service import JobQueue

SLA_MS = 200


# -- Helpers y fixtures -------------------------------------------------------


def _create_test_queue(max_concurrent: int = 2, max_queue_size: int = 200) -> JobQueue:
    return JobQueue(max_concurrent=max_concurrent, max_queue_size=max_queue_size)


@pytest.fixture
def scans_client():
    queue = _create_test_queue()
    app.dependency_overrides[get_job_queue] = lambda: queue
    yield TestClient(app), queue
    app.dependency_overrides.clear()


def _force_done(queue: JobQueue, scan_id: str, result: dict) -> None:
    """Fuerza un job a estado DONE con un resultado dado (sin correr un scanner real)."""
    job = queue.get_job(UUID(scan_id))
    job.transition_to(JobStatus.RUNNING)
    job.result = result
    job.transition_to(JobStatus.DONE)


def _force_failed(queue: JobQueue, scan_id: str, error: str) -> None:
    job = queue.get_job(UUID(scan_id))
    job.transition_to(JobStatus.RUNNING)
    job.error = error
    job.transition_to(JobStatus.FAILED)


def _vuln_finding(index: int, severity: str = "high") -> dict:
    return {
        "template_id": f"finding-{index:03d}",
        "name": f"Vuln {index}",
        "severity": severity,
        "host": "example.com",
        "matched_at": f"https://example.com/{index}",
        "tags": ["web"],
    }


def _host_finding(address: str, status: str) -> dict:
    return {
        "address": address,
        "status": status,
        "ports": [{"port": 80, "protocol": "tcp", "service": "http", "version": "1.0"}],
    }


# -- Escaneo no encontrado ------------------------------------------------------


class TestGetScanDetailNotFound:
    def test_returns_404_for_nonexistent_scan(self, scans_client) -> None:
        client, _ = scans_client

        response = client.get("/api/scans/00000000-0000-0000-0000-000000000000")

        assert response.status_code == 404


# -- Respuesta coherente durante ejecución (spec requirement) ------------------


class TestGetScanDetailWhileRunning:
    def test_pending_scan_returns_coherent_empty_response(self, scans_client) -> None:
        client, _ = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "10.0.0.1", "scan_type": "discovery"}
        )
        scan_id = post_resp.json()["scan_id"]

        response = client.get(f"/api/scans/{scan_id}")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "pending"
        assert body["progress"] == 0.0
        assert body["assets"] == []
        assert body["findings"]["items"] == []
        assert body["findings"]["total"] == 0
        assert body["error"] is None

    def test_running_scan_returns_coherent_response(self, scans_client) -> None:
        client, queue = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "10.0.0.2", "scan_type": "vulnscan"}
        )
        scan_id = post_resp.json()["scan_id"]
        queue.get_job(UUID(scan_id)).transition_to(JobStatus.RUNNING)

        response = client.get(f"/api/scans/{scan_id}")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "running"
        assert body["progress"] == 0.5
        assert body["findings"]["items"] == []

    def test_failed_scan_includes_error_and_coherent_empty_results(self, scans_client) -> None:
        client, queue = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "10.0.0.3", "scan_type": "discovery"}
        )
        scan_id = post_resp.json()["scan_id"]
        _force_failed(queue, scan_id, "Host inalcanzable")

        response = client.get(f"/api/scans/{scan_id}")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "failed"
        assert body["progress"] == 1.0
        assert body["error"] == "Host inalcanzable"
        assert body["assets"] == []


# -- Activos descubiertos (discovery) -------------------------------------------


class TestGetScanDetailAssets:
    def test_done_discovery_scan_returns_assets(self, scans_client) -> None:
        client, queue = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "10.0.0.4", "scan_type": "discovery"}
        )
        scan_id = post_resp.json()["scan_id"]
        _force_done(
            queue,
            scan_id,
            {
                "target": "10.0.0.4",
                "port_range": "1-1024",
                "status": "completed",
                "hosts": [_host_finding("10.0.0.4", "up"), _host_finding("10.0.0.5", "down")],
            },
        )

        response = client.get(f"/api/scans/{scan_id}")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "done"
        assert body["progress"] == 1.0
        assert len(body["assets"]) == 2
        assert body["findings"]["items"] == []

    def test_filter_assets_by_status(self, scans_client) -> None:
        client, queue = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "10.0.0.6", "scan_type": "discovery"}
        )
        scan_id = post_resp.json()["scan_id"]
        _force_done(
            queue,
            scan_id,
            {
                "target": "10.0.0.6",
                "port_range": "1-1024",
                "status": "completed",
                "hosts": [_host_finding("10.0.0.6", "up"), _host_finding("10.0.0.7", "down")],
            },
        )

        response = client.get(f"/api/scans/{scan_id}", params={"asset_status": "up"})

        assert response.status_code == 200
        assets = response.json()["assets"]
        assert len(assets) == 1
        assert assets[0]["address"] == "10.0.0.6"


# -- Hallazgos paginados (vulnscan) ---------------------------------------------


class TestGetScanDetailFindingsPagination:
    def test_findings_are_paginated(self, scans_client) -> None:
        client, queue = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "example.com", "scan_type": "vulnscan"}
        )
        scan_id = post_resp.json()["scan_id"]
        findings = [_vuln_finding(i) for i in range(25)]
        _force_done(
            queue, scan_id, {"target": "example.com", "status": "completed", "findings": findings}
        )

        response = client.get(f"/api/scans/{scan_id}", params={"page": 1, "page_size": 10})

        assert response.status_code == 200
        body = response.json()["findings"]
        assert len(body["items"]) == 10
        assert body["total"] == 25
        assert body["page"] == 1
        assert body["page_size"] == 10
        assert body["total_pages"] == 3

    def test_second_page_returns_remaining_items(self, scans_client) -> None:
        client, queue = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "example.com", "scan_type": "vulnscan"}
        )
        scan_id = post_resp.json()["scan_id"]
        findings = [_vuln_finding(i) for i in range(25)]
        _force_done(
            queue, scan_id, {"target": "example.com", "status": "completed", "findings": findings}
        )

        response = client.get(f"/api/scans/{scan_id}", params={"page": 3, "page_size": 10})

        body = response.json()["findings"]
        assert len(body["items"]) == 5
        assert body["page"] == 3

    def test_page_beyond_range_returns_empty_items_not_error(self, scans_client) -> None:
        client, queue = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "example.com", "scan_type": "vulnscan"}
        )
        scan_id = post_resp.json()["scan_id"]
        _force_done(
            queue,
            scan_id,
            {"target": "example.com", "status": "completed", "findings": [_vuln_finding(0)]},
        )

        response = client.get(f"/api/scans/{scan_id}", params={"page": 99, "page_size": 10})

        assert response.status_code == 200
        body = response.json()["findings"]
        assert body["items"] == []
        assert body["total"] == 1

    def test_invalid_page_size_returns_422(self, scans_client) -> None:
        client, queue = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "example.com", "scan_type": "vulnscan"}
        )
        scan_id = post_resp.json()["scan_id"]

        response = client.get(f"/api/scans/{scan_id}", params={"page_size": 0})

        assert response.status_code == 422

    def test_invalid_page_returns_422(self, scans_client) -> None:
        client, queue = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "example.com", "scan_type": "vulnscan"}
        )
        scan_id = post_resp.json()["scan_id"]

        response = client.get(f"/api/scans/{scan_id}", params={"page": 0})

        assert response.status_code == 422


# -- Filtrado por severidad ------------------------------------------------------


class TestGetScanDetailSeverityFilter:
    def test_filter_findings_by_severity(self, scans_client) -> None:
        client, queue = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "example.com", "scan_type": "vulnscan"}
        )
        scan_id = post_resp.json()["scan_id"]
        findings = [_vuln_finding(0, "high"), _vuln_finding(1, "low"), _vuln_finding(2, "high")]
        _force_done(
            queue, scan_id, {"target": "example.com", "status": "completed", "findings": findings}
        )

        response = client.get(f"/api/scans/{scan_id}", params={"severity": "high"})

        body = response.json()["findings"]
        assert body["total"] == 2
        assert all(f["severity"] == "high" for f in body["items"])

    def test_invalid_severity_returns_422(self, scans_client) -> None:
        client, queue = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "example.com", "scan_type": "vulnscan"}
        )
        scan_id = post_resp.json()["scan_id"]

        response = client.get(f"/api/scans/{scan_id}", params={"severity": "not_a_severity"})

        assert response.status_code == 422


# -- Tiempos de respuesta medidos (DoD) ------------------------------------------


class TestGetScanDetailResponseTime:
    """Scenario: Tiempo de respuesta medido en entorno de prueba (DoD)."""

    def test_response_under_sla_with_large_findings_list(self, scans_client) -> None:
        client, queue = scans_client

        post_resp = client.post(
            "/api/scans", json={"target": "example.com", "scan_type": "vulnscan"}
        )
        scan_id = post_resp.json()["scan_id"]
        findings = [_vuln_finding(i, "high" if i % 2 == 0 else "low") for i in range(200)]
        _force_done(
            queue, scan_id, {"target": "example.com", "status": "completed", "findings": findings}
        )

        start = time.perf_counter()
        response = client.get(f"/api/scans/{scan_id}", params={"page": 1, "page_size": 50})
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert response.status_code == 200
        assert elapsed_ms < SLA_MS
