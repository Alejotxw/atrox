"""Tests unitarios para el router de trabajos /api/jobs (HU-004, Fases 4-6)."""

import asyncio
import threading

import pytest
from fastapi.testclient import TestClient

from atrox.api.jobs import get_job_queue
from atrox.main import app
from atrox.queue.models import Job, JobStatus, JobType
from atrox.queue.service import JobQueue


# -- Helpers y fixtures -------------------------------------------------------


def _create_test_queue(max_concurrent: int = 2, max_queue_size: int = 10) -> JobQueue:
    """Crea un JobQueue con configuracion de test."""
    return JobQueue(max_concurrent=max_concurrent, max_queue_size=max_queue_size)


async def _mock_scanner(job: Job) -> dict:
    """Scanner mock que retorna resultado inmediato."""
    return {"resultado": "ok", "target": job.params.get("target", "")}


@pytest.fixture
def jobs_client():
    """TestClient con DI override de get_job_queue (cola fresca por test)."""
    queue = _create_test_queue()
    app.dependency_overrides[get_job_queue] = lambda: queue
    yield TestClient(app), queue
    app.dependency_overrides.clear()


# -- Fase 4: API Layer -------------------------------------------------------


# -- POST /api/jobs returns 202 -----------------------------------------------


class TestPostJobs:
    """Scenario: Submit job via POST /api/jobs (spec requirement)."""

    def test_post_jobs_returns_202_with_job_id(self, jobs_client) -> None:
        client, _ = jobs_client

        response = client.post(
            "/api/jobs",
            json={
                "type": "discovery",
                "target": "192.168.1.1",
                "params": {"port_range": "80,443"},
            },
        )

        assert response.status_code == 202
        body = response.json()
        assert "job_id" in body
        assert body["status"] == "pending"

    def test_post_vulnscan_job_returns_202(self, jobs_client) -> None:
        client, _ = jobs_client

        response = client.post(
            "/api/jobs",
            json={
                "type": "vulnscan",
                "target": "example.com",
                "params": {},
            },
        )

        assert response.status_code == 202
        body = response.json()
        assert "job_id" in body
        assert body["status"] == "pending"


# -- POST with invalid target returns 422 -------------------------------------


class TestPostJobsValidation:
    """Scenario: Submit with invalid target (spec requirement)."""

    def test_invalid_target_returns_422(self, jobs_client) -> None:
        client, _ = jobs_client

        response = client.post(
            "/api/jobs",
            json={"type": "discovery", "target": "not_valid!!!", "params": {}},
        )

        assert response.status_code == 422

    def test_empty_target_returns_422(self, jobs_client) -> None:
        client, _ = jobs_client

        response = client.post(
            "/api/jobs",
            json={"type": "discovery", "target": "", "params": {}},
        )

        assert response.status_code == 422

    def test_params_default_is_not_shared_between_instances(self, jobs_client) -> None:
        """Verifica que el default de params no es un dict mutable compartido."""
        from atrox.api.jobs import JobSubmitRequest

        req1 = JobSubmitRequest(type=JobType.DISCOVERY, target="192.168.1.1")
        req2 = JobSubmitRequest(type=JobType.DISCOVERY, target="192.168.1.2")

        # Mutamos params de req1 — NO debe afectar a req2
        req1.params["injected"] = True

        assert "injected" not in req2.params
        assert req2.params == {}


# -- GET /api/jobs/{job_id} returns job; 404 for nonexistent -------------------


class TestGetJobById:
    """Scenario: Poll job status (spec requirement)."""

    def test_get_existing_job_returns_200(self, jobs_client) -> None:
        client, _ = jobs_client

        post_resp = client.post(
            "/api/jobs",
            json={"type": "discovery", "target": "192.168.1.1", "params": {}},
        )
        job_id = post_resp.json()["job_id"]

        get_resp = client.get(f"/api/jobs/{job_id}")

        assert get_resp.status_code == 200
        body = get_resp.json()
        assert body["id"] == job_id
        assert body["status"] == "pending"
        assert body["job_type"] == "discovery"

    def test_get_nonexistent_job_returns_404(self, jobs_client) -> None:
        client, _ = jobs_client

        response = client.get("/api/jobs/00000000-0000-0000-0000-000000000000")

        assert response.status_code == 404


class TestPollFailedJob:
    """Scenario: Poll failed job (spec requirement).

    GIVEN a job that failed, WHEN GET /api/jobs/{job_id},
    THEN response includes status 'failed' and error message.
    """

    def test_poll_failed_job_returns_status_failed_and_error(self) -> None:
        """Envia un trabajo que fallara, lo procesa, y verifica status + error."""
        queue = _create_test_queue(max_concurrent=2, max_queue_size=10)
        app.dependency_overrides[get_job_queue] = lambda: queue

        async def failing_scanner(job: Job) -> dict:
            raise RuntimeError("Conexion rechazada por el host")

        loop = asyncio.new_event_loop()
        loop.run_until_complete(queue.start(scanner=failing_scanner))

        client = TestClient(app)

        post_resp = client.post(
            "/api/jobs",
            json={"type": "discovery", "target": "192.168.1.1", "params": {}},
        )
        assert post_resp.status_code == 202
        job_id = post_resp.json()["job_id"]

        # Esperar a que el worker procese el trabajo (y falle)
        status = "pending"
        for _ in range(50):
            loop.run_until_complete(asyncio.sleep(0.1))
            get_resp = client.get(f"/api/jobs/{job_id}")
            assert get_resp.status_code == 200
            body = get_resp.json()
            status = body["status"]
            if status in ("done", "failed"):
                break

        loop.run_until_complete(queue.shutdown())
        loop.close()
        app.dependency_overrides.clear()

        assert status == "failed"
        assert body["error"] == "Conexion rechazada por el host"

    def test_poll_failed_job_has_error_field_not_none(self) -> None:
        """Verifica que el campo error no es None en un trabajo fallido."""
        queue = _create_test_queue(max_concurrent=2, max_queue_size=10)
        app.dependency_overrides[get_job_queue] = lambda: queue

        async def failing_scanner(job: Job) -> dict:
            raise ValueError("Parametro invalido")

        loop = asyncio.new_event_loop()
        loop.run_until_complete(queue.start(scanner=failing_scanner))

        client = TestClient(app)

        post_resp = client.post(
            "/api/jobs",
            json={"type": "vulnscan", "target": "example.com", "params": {}},
        )
        job_id = post_resp.json()["job_id"]

        for _ in range(50):
            loop.run_until_complete(asyncio.sleep(0.1))
            get_resp = client.get(f"/api/jobs/{job_id}")
            body = get_resp.json()
            if body["status"] in ("done", "failed"):
                break

        loop.run_until_complete(queue.shutdown())
        loop.close()
        app.dependency_overrides.clear()

        assert body["status"] == "failed"
        assert body["error"] is not None
        assert "Parametro invalido" in body["error"]


# -- GET /api/jobs returns list ------------------------------------------------


class TestListJobs:
    """Scenario: List jobs (spec requirement)."""

    def test_list_jobs_returns_array(self, jobs_client) -> None:
        client, _ = jobs_client

        client.post("/api/jobs", json={"type": "discovery", "target": "10.0.0.1", "params": {}})
        client.post("/api/jobs", json={"type": "vulnscan", "target": "10.0.0.2", "params": {}})
        client.post("/api/jobs", json={"type": "discovery", "target": "10.0.0.3", "params": {}})

        response = client.get("/api/jobs")

        assert response.status_code == 200
        body = response.json()
        assert isinstance(body, list)
        assert len(body) == 3

    def test_list_jobs_empty_returns_empty_array(self, jobs_client) -> None:
        client, _ = jobs_client

        response = client.get("/api/jobs")

        assert response.status_code == 200
        assert response.json() == []


# -- GET /api/jobs/metrics returns QueueMetrics --------------------------------


class TestGetMetrics:
    """Scenario: Queue metrics (spec requirement)."""

    def test_metrics_returns_200_with_queue_metrics(self, jobs_client) -> None:
        client, _ = jobs_client

        response = client.get("/api/jobs/metrics")

        assert response.status_code == 200
        body = response.json()
        assert "queue_depth" in body
        assert "active_jobs" in body
        assert "completed_count" in body
        assert "failed_count" in body
        assert "avg_duration_seconds" in body

    def test_metrics_after_submitting_jobs(self, jobs_client) -> None:
        client, _ = jobs_client

        client.post("/api/jobs", json={"type": "discovery", "target": "10.0.0.1", "params": {}})
        client.post("/api/jobs", json={"type": "discovery", "target": "10.0.0.2", "params": {}})

        response = client.get("/api/jobs/metrics")

        assert response.status_code == 200
        body = response.json()
        assert body["queue_depth"] == 2
        assert body["active_jobs"] == 0
        assert body["completed_count"] == 0


# -- POST returns 503 when queue full ------------------------------------------


class TestQueueFullApi:
    """Scenario: Queue full rejection via API (spec requirement)."""

    def test_post_returns_503_when_queue_full(self) -> None:
        queue = _create_test_queue(max_concurrent=1, max_queue_size=2)
        app.dependency_overrides[get_job_queue] = lambda: queue
        client = TestClient(app)

        resp1 = client.post("/api/jobs", json={"type": "discovery", "target": "10.0.0.1", "params": {}})
        resp2 = client.post("/api/jobs", json={"type": "discovery", "target": "10.0.0.2", "params": {}})
        assert resp1.status_code == 202
        assert resp2.status_code == 202

        overflow_resp = client.post(
            "/api/jobs",
            json={"type": "discovery", "target": "10.0.0.3", "params": {}},
        )

        app.dependency_overrides.clear()

        assert overflow_resp.status_code == 503

    def test_503_response_includes_error_detail(self) -> None:
        queue = _create_test_queue(max_concurrent=1, max_queue_size=1)
        app.dependency_overrides[get_job_queue] = lambda: queue
        client = TestClient(app)

        client.post("/api/jobs", json={"type": "discovery", "target": "10.0.0.1", "params": {}})
        overflow_resp = client.post(
            "/api/jobs",
            json={"type": "discovery", "target": "10.0.0.2", "params": {}},
        )

        app.dependency_overrides.clear()

        assert overflow_resp.status_code == 503
        body = overflow_resp.json()
        assert "detail" in body


# -- Fase 5: Integration -- Lifespan and Wiring ------------------------------


class TestEndToEndJobFlow:
    """Scenario: Submit job via API, poll until done (spec requirement)."""

    def test_submit_and_poll_until_done(self) -> None:
        """Envia un trabajo, inicia workers, y verifica que se complete."""
        queue = _create_test_queue(max_concurrent=2, max_queue_size=10)
        app.dependency_overrides[get_job_queue] = lambda: queue

        loop = asyncio.new_event_loop()
        loop.run_until_complete(queue.start(scanner=_mock_scanner))

        client = TestClient(app)

        post_resp = client.post(
            "/api/jobs",
            json={"type": "discovery", "target": "192.168.1.1", "params": {"port_range": "80"}},
        )
        assert post_resp.status_code == 202
        job_id = post_resp.json()["job_id"]

        status = "pending"
        for _ in range(50):
            loop.run_until_complete(asyncio.sleep(0.1))
            get_resp = client.get(f"/api/jobs/{job_id}")
            assert get_resp.status_code == 200
            status = get_resp.json()["status"]
            if status in ("done", "failed"):
                break

        loop.run_until_complete(queue.shutdown())
        loop.close()
        app.dependency_overrides.clear()

        assert status == "done"

    def test_lifespan_creates_job_queue_in_app_state(self) -> None:
        """Verifica que la lifespan de la app crea job_queue en app.state."""
        with TestClient(app) as client:
            response = client.get("/api/jobs")
            assert response.status_code == 200

    def test_lifespan_starts_workers_on_job_queue(self) -> None:
        """Verifica que la lifespan llama a queue.start() (workers creados)."""
        with TestClient(app) as client:
            queue: JobQueue = client.app.state.job_queue
            assert len(queue._workers) > 0, "lifespan debe llamar queue.start()"

    def test_lifespan_creates_executor_from_parse_workers(self) -> None:
        """Verifica que la lifespan crea ProcessPoolExecutor con parse_workers."""
        with TestClient(app) as client:
            queue: JobQueue = client.app.state.job_queue
            assert queue._executor is not None, (
                "lifespan debe crear un executor para parseo CPU-bound"
            )

    def test_existing_health_endpoint_still_works(self) -> None:
        """Verifica que /health sigue funcionando con el router de jobs registrado."""
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200

    def test_existing_discovery_endpoint_still_available(self) -> None:
        """Verifica que la ruta /api/discovery/scan sigue registrada."""
        from atrox.api.discovery import get_nmap_wrapper
        from atrox.scanner.nmap_wrapper import NmapWrapper
        from tests.fixtures.nmap_samples import SAMPLE_NMAP_XML_UP

        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, SAMPLE_NMAP_XML_UP, ""

        app.dependency_overrides[get_nmap_wrapper] = lambda: NmapWrapper(runner=mock_runner)
        client = TestClient(app)

        response = client.post(
            "/api/discovery/scan",
            json={"target": "192.168.1.1", "port_range": "22"},
        )

        app.dependency_overrides.clear()

        assert response.status_code == 200


# -- Fase 6: Load Test -- Concurrency Validation -----------------------------


class TestConcurrencyLoad:
    """Test de carga: validacion de concurrencia con multiples trabajos simultaneos.

    Estos tests verifican que:
    - Multiples trabajos se procesan correctamente en paralelo
    - El semaforo limita la cantidad de trabajos activos simultaneamente
    - Las metricas reflejan el estado correcto despues de la carga

    Para ejecutar manualmente:
        pytest tests/test_jobs_api.py::TestConcurrencyLoad -v
    """

    def test_10_concurrent_jobs_all_complete(self) -> None:
        """Envia 10 trabajos simultaneos y verifica que todos se completen."""
        max_concurrent = 3
        num_jobs = 10
        queue = _create_test_queue(max_concurrent=max_concurrent, max_queue_size=20)
        app.dependency_overrides[get_job_queue] = lambda: queue

        async def slow_scanner(job: Job) -> dict:
            """Scanner que simula procesamiento con un pequeno delay."""
            await asyncio.sleep(0.05)
            return {"target": job.params.get("target", ""), "resultado": "completado"}

        loop = asyncio.new_event_loop()
        loop.run_until_complete(queue.start(scanner=slow_scanner))

        client = TestClient(app)

        job_ids = []
        for i in range(num_jobs):
            resp = client.post(
                "/api/jobs",
                json={"type": "discovery", "target": f"10.0.0.{i + 1}", "params": {}},
            )
            assert resp.status_code == 202
            job_ids.append(resp.json()["job_id"])

        for _ in range(100):
            loop.run_until_complete(asyncio.sleep(0.1))
            metrics_resp = client.get("/api/jobs/metrics")
            metrics = metrics_resp.json()
            if metrics["completed_count"] + metrics["failed_count"] == num_jobs:
                break

        loop.run_until_complete(queue.shutdown())
        loop.close()
        app.dependency_overrides.clear()

        assert metrics["completed_count"] == num_jobs
        assert metrics["failed_count"] == 0
        assert metrics["queue_depth"] == 0
        assert metrics["active_jobs"] == 0

    def test_semaphore_limits_concurrent_execution(self) -> None:
        """Verifica que el semaforo limita la ejecucion simultanea."""
        max_concurrent = 2
        num_jobs = 6
        peak_concurrent = 0
        lock = threading.Lock()
        current_running = 0

        queue = _create_test_queue(max_concurrent=max_concurrent, max_queue_size=20)
        app.dependency_overrides[get_job_queue] = lambda: queue

        async def tracking_scanner(job: Job) -> dict:
            """Scanner que rastrea la concurrencia maxima observada."""
            nonlocal peak_concurrent, current_running
            with lock:
                current_running += 1
                peak_concurrent = max(peak_concurrent, current_running)
            await asyncio.sleep(0.15)
            with lock:
                current_running -= 1
            return {"resultado": "ok"}

        loop = asyncio.new_event_loop()
        loop.run_until_complete(queue.start(scanner=tracking_scanner))

        client = TestClient(app)

        for i in range(num_jobs):
            client.post(
                "/api/jobs",
                json={"type": "discovery", "target": f"10.0.0.{i + 1}", "params": {}},
            )

        for _ in range(100):
            loop.run_until_complete(asyncio.sleep(0.1))
            metrics = client.get("/api/jobs/metrics").json()
            if metrics["completed_count"] == num_jobs:
                break

        loop.run_until_complete(queue.shutdown())
        loop.close()
        app.dependency_overrides.clear()

        assert peak_concurrent <= max_concurrent
        assert metrics["completed_count"] == num_jobs

    def test_metrics_correct_after_load(self) -> None:
        """Verifica que las metricas reflejan el estado correcto post-carga."""
        num_success = 7
        num_fail = 3
        total = num_success + num_fail
        queue = _create_test_queue(max_concurrent=3, max_queue_size=20)
        app.dependency_overrides[get_job_queue] = lambda: queue

        async def mixed_scanner(job: Job) -> dict:
            """Scanner que falla para los ultimos num_fail trabajos."""
            await asyncio.sleep(0.03)
            idx = int(job.params["target"].split(".")[-1])
            if idx > num_success:
                raise RuntimeError(f"Error simulado para {job.params['target']}")
            return {"resultado": "ok"}

        loop = asyncio.new_event_loop()
        loop.run_until_complete(queue.start(scanner=mixed_scanner))

        client = TestClient(app)

        for i in range(total):
            client.post(
                "/api/jobs",
                json={"type": "discovery", "target": f"10.0.0.{i + 1}", "params": {}},
            )

        for _ in range(100):
            loop.run_until_complete(asyncio.sleep(0.1))
            metrics = client.get("/api/jobs/metrics").json()
            if metrics["completed_count"] + metrics["failed_count"] == total:
                break

        loop.run_until_complete(queue.shutdown())
        loop.close()
        app.dependency_overrides.clear()

        assert metrics["completed_count"] == num_success
        assert metrics["failed_count"] == num_fail
        assert metrics["queue_depth"] == 0
        assert metrics["active_jobs"] == 0
        assert metrics["avg_duration_seconds"] > 0.0
