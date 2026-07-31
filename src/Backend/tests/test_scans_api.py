"""Tests unitarios para el router REST de escaneos /api/scans (HU-009)."""

from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from atrox.api.jobs import get_job_queue
from atrox.main import app
from atrox.queue.service import JobQueue


# -- Helpers y fixtures -------------------------------------------------------


def _create_test_queue(max_concurrent: int = 2, max_queue_size: int = 10) -> JobQueue:
    """Crea un JobQueue con configuracion de test."""
    return JobQueue(max_concurrent=max_concurrent, max_queue_size=max_queue_size)


@pytest.fixture
def scans_client():
    """TestClient con DI override de get_job_queue (cola fresca por test)."""
    queue = _create_test_queue()
    app.dependency_overrides[get_job_queue] = lambda: queue
    yield TestClient(app), queue
    app.dependency_overrides.clear()


# -- POST /api/scans crea el escaneo y retorna scan_id + estado inicial -------


class TestPostScans:
    """Scenario: Crear un escaneo vía POST /api/scans (spec requirement)."""

    def test_post_scans_returns_202_with_scan_id_and_pending_status(self, scans_client) -> None:
        client, _ = scans_client

        response = client.post(
            "/api/scans",
            json={
                "target": "192.168.1.1",
                "scan_type": "discovery",
                "params": {"port_range": "80,443"},
            },
        )

        assert response.status_code == 202
        body = response.json()
        assert "scan_id" in body
        assert body["status"] == "pending"

    def test_post_scans_vulnscan_type(self, scans_client) -> None:
        client, _ = scans_client

        response = client.post(
            "/api/scans",
            json={"target": "example.com", "scan_type": "vulnscan"},
        )

        assert response.status_code == 202
        assert response.json()["status"] == "pending"

    def test_post_scans_enqueues_job_in_hu004_queue(self, scans_client) -> None:
        """El escaneo creado debe existir como Job encolado (integración con HU-004)."""
        client, queue = scans_client

        response = client.post(
            "/api/scans",
            json={"target": "10.0.0.5", "scan_type": "discovery"},
        )
        scan_id = response.json()["scan_id"]

        job = queue.get_job(UUID(scan_id))
        assert job is not None
        assert job.job_type.value == "discovery"
        assert job.params["target"] == "10.0.0.5"

    def test_post_scans_reachable_via_existing_jobs_endpoint(self, scans_client) -> None:
        """scan_id es el mismo ID que job_id: se puede consultar vía GET /api/jobs/{id}."""
        client, _ = scans_client

        response = client.post(
            "/api/scans", json={"target": "10.0.0.6", "scan_type": "discovery"}
        )
        scan_id = response.json()["scan_id"]

        get_resp = client.get(f"/api/jobs/{scan_id}")

        assert get_resp.status_code == 200
        assert get_resp.json()["status"] == "pending"


# -- Payload invalido retorna 422 ---------------------------------------------


class TestPostScansValidation:
    """Scenario: Validación de objetivo y tipo de escaneo (spec requirement)."""

    def test_invalid_target_returns_422(self, scans_client) -> None:
        client, _ = scans_client

        response = client.post(
            "/api/scans", json={"target": "not_valid!!!", "scan_type": "discovery"}
        )

        assert response.status_code == 422

    def test_empty_target_returns_422(self, scans_client) -> None:
        client, _ = scans_client

        response = client.post(
            "/api/scans", json={"target": "", "scan_type": "discovery"}
        )

        assert response.status_code == 422

    def test_missing_scan_type_returns_422(self, scans_client) -> None:
        client, _ = scans_client

        response = client.post("/api/scans", json={"target": "10.0.0.1"})

        assert response.status_code == 422

    def test_invalid_scan_type_returns_422(self, scans_client) -> None:
        client, _ = scans_client

        response = client.post(
            "/api/scans", json={"target": "10.0.0.1", "scan_type": "not_a_type"}
        )

        assert response.status_code == 422


# -- Cola llena rechaza nuevos escaneos (integración HU-004) ------------------


class TestPostScansQueueFull:
    """Scenario: Cola llena rechaza nuevos escaneos vía API (spec requirement)."""

    def test_post_returns_503_when_queue_full(self) -> None:
        queue = _create_test_queue(max_concurrent=1, max_queue_size=2)
        app.dependency_overrides[get_job_queue] = lambda: queue
        client = TestClient(app)

        resp1 = client.post(
            "/api/scans", json={"target": "10.0.0.1", "scan_type": "discovery"}
        )
        resp2 = client.post(
            "/api/scans", json={"target": "10.0.0.2", "scan_type": "discovery"}
        )
        assert resp1.status_code == 202
        assert resp2.status_code == 202

        overflow_resp = client.post(
            "/api/scans", json={"target": "10.0.0.3", "scan_type": "discovery"}
        )

        app.dependency_overrides.clear()

        assert overflow_resp.status_code == 503
