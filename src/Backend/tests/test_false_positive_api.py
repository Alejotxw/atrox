"""Tests unitarios para el marcado manual de falsos positivos vía API (HU-022)."""

import asyncio
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from atrox.api.jobs import get_job_queue
from atrox.api.scans import get_false_positive_store
from atrox.findings.store import FalsePositiveStore
from atrox.main import app
from atrox.queue.models import JobStatus
from atrox.queue.service import JobQueue
from atrox.security.audit_service import AuditLogService, AuditLogStore
from atrox.security.audit_signer import AuditSigner, decode_signing_key, generate_signing_key


def _create_test_queue(max_concurrent: int = 2, max_queue_size: int = 10) -> JobQueue:
    return JobQueue(max_concurrent=max_concurrent, max_queue_size=max_queue_size)


def _force_done(queue: JobQueue, scan_id: str, result: dict) -> None:
    job = queue.get_job(UUID(scan_id))
    job.transition_to(JobStatus.RUNNING)
    job.result = result
    job.transition_to(JobStatus.DONE)


def _vuln_finding(template_id: str = "cve-2021-41773", **overrides) -> dict:
    data = {
        "template_id": template_id,
        "name": "Apache Path Traversal",
        "severity": "critical",
        "host": "http://example.com",
        "matched_at": "http://example.com/traversal",
        "tags": ["cve", "rce"],
        "description": "Path traversal confirmado.",
        "extracted_results": ["root:x:0:0:root:/root:/bin/bash"],
    }
    data.update(overrides)
    return data


@pytest.fixture
def fp_store(tmp_path: Path) -> FalsePositiveStore:
    return FalsePositiveStore(store_path=tmp_path / "false_positives.jsonl")


@pytest.fixture
def scans_client(fp_store: FalsePositiveStore):
    queue = _create_test_queue()
    app.dependency_overrides[get_job_queue] = lambda: queue
    app.dependency_overrides[get_false_positive_store] = lambda: fp_store
    yield TestClient(app), queue
    app.dependency_overrides.clear()


def _create_vulnscan_with_finding(client: TestClient, queue: JobQueue, finding: dict) -> str:
    resp = client.post("/api/scans", json={"target": "example.com", "scan_type": "vulnscan"})
    scan_id = resp.json()["scan_id"]
    _force_done(queue, scan_id, {"target": "example.com", "status": "completed", "findings": [finding]})
    return scan_id


# -- La accion persiste estado false_positive con usuario y timestamp (spec) ---


class TestMarkFalsePositiveApi:
    def test_mark_returns_201_with_user_and_timestamp(self, scans_client) -> None:
        client, queue = scans_client
        finding = _vuln_finding()
        scan_id = _create_vulnscan_with_finding(client, queue, finding)

        response = client.post(
            f"/api/scans/{scan_id}/findings/false-positive",
            json={"finding": finding},
            headers={"X-Atrox-User": "analyst1"},
        )

        assert response.status_code == 201
        body = response.json()
        assert body["user"] == "analyst1"
        assert body["marked_at"] is not None
        assert body["finding_id"] == finding["template_id"]
        assert body["scan_id"] == scan_id

    def test_mark_defaults_user_to_system_without_header(self, scans_client) -> None:
        client, queue = scans_client
        finding = _vuln_finding()
        scan_id = _create_vulnscan_with_finding(client, queue, finding)

        response = client.post(
            f"/api/scans/{scan_id}/findings/false-positive", json={"finding": finding}
        )

        assert response.json()["user"] == "system"

    def test_mark_missing_finding_returns_422(self, scans_client) -> None:
        client, queue = scans_client
        scan_id = _create_vulnscan_with_finding(client, queue, _vuln_finding())

        response = client.post(f"/api/scans/{scan_id}/findings/false-positive", json={})

        assert response.status_code == 422

    def test_mark_accepts_optional_reason(self, scans_client) -> None:
        client, queue = scans_client
        finding = _vuln_finding()
        scan_id = _create_vulnscan_with_finding(client, queue, finding)

        response = client.post(
            f"/api/scans/{scan_id}/findings/false-positive",
            json={"finding": finding, "reason": "Banner grab genérico"},
        )

        assert response.json()["reason"] == "Banner grab genérico"


# -- Dato disponible para reentrenamiento/heurística futura (DoD) --------------


class TestListFalsePositivesApi:
    def test_list_returns_marked_findings_for_scan(self, scans_client) -> None:
        client, queue = scans_client
        finding = _vuln_finding()
        scan_id = _create_vulnscan_with_finding(client, queue, finding)
        client.post(f"/api/scans/{scan_id}/findings/false-positive", json={"finding": finding})

        response = client.get(f"/api/scans/{scan_id}/findings/false-positives")

        assert response.status_code == 200
        body = response.json()
        assert len(body) == 1
        assert body[0]["finding"]["template_id"] == finding["template_id"]

    def test_list_empty_when_nothing_marked(self, scans_client) -> None:
        client, queue = scans_client
        scan_id = _create_vulnscan_with_finding(client, queue, _vuln_finding())

        response = client.get(f"/api/scans/{scan_id}/findings/false-positives")

        assert response.json() == []


# -- Hallazgo excluido de reportes por defecto — integración con HU-010 --------


class TestFalsePositiveExclusionFromScanDetail:
    def test_marked_finding_excluded_from_scan_detail_by_default(self, scans_client) -> None:
        client, queue = scans_client
        finding = _vuln_finding()
        scan_id = _create_vulnscan_with_finding(client, queue, finding)

        client.post(f"/api/scans/{scan_id}/findings/false-positive", json={"finding": finding})
        response = client.get(f"/api/scans/{scan_id}")

        assert response.json()["findings"]["items"] == []
        assert response.json()["findings"]["total"] == 0

    def test_include_false_positives_true_shows_marked_finding(self, scans_client) -> None:
        client, queue = scans_client
        finding = _vuln_finding()
        scan_id = _create_vulnscan_with_finding(client, queue, finding)

        client.post(f"/api/scans/{scan_id}/findings/false-positive", json={"finding": finding})
        response = client.get(f"/api/scans/{scan_id}", params={"include_false_positives": "true"})

        assert response.json()["findings"]["total"] == 1

    def test_unmarked_finding_still_shown_by_default(self, scans_client) -> None:
        client, queue = scans_client
        marked = _vuln_finding(template_id="marked-one", matched_at="http://example.com/a")
        unmarked = _vuln_finding(template_id="unmarked-one", matched_at="http://example.com/b")
        resp = client.post("/api/scans", json={"target": "example.com", "scan_type": "vulnscan"})
        scan_id = resp.json()["scan_id"]
        _force_done(
            queue,
            scan_id,
            {"target": "example.com", "status": "completed", "findings": [marked, unmarked]},
        )

        client.post(f"/api/scans/{scan_id}/findings/false-positive", json={"finding": marked})
        response = client.get(f"/api/scans/{scan_id}")

        items = response.json()["findings"]["items"]
        assert len(items) == 1
        assert items[0]["template_id"] == "unmarked-one"


# -- Evento registrado en HU-008 -------------------------------------------------


class TestFalsePositiveAuditIntegration:
    def test_mark_records_audit_event(self, fp_store: FalsePositiveStore, tmp_path: Path) -> None:
        queue = _create_test_queue()
        signing_key = generate_signing_key()
        audit_store = AuditLogStore(tmp_path / "audit.log", retention_days=30)
        audit_service = AuditLogService(
            store=audit_store, signer=AuditSigner(decode_signing_key(signing_key))
        )

        app.dependency_overrides[get_job_queue] = lambda: queue
        app.dependency_overrides[get_false_positive_store] = lambda: fp_store
        app.state.audit_log = audit_service
        client = TestClient(app)

        finding = _vuln_finding()
        scan_id = _create_vulnscan_with_finding(client, queue, finding)
        client.post(
            f"/api/scans/{scan_id}/findings/false-positive",
            json={"finding": finding},
            headers={"X-Atrox-User": "analyst1"},
        )

        entries, verified, tampered = asyncio.run(
            audit_service.query(action="finding.marked_false_positive")
        )

        app.state.audit_log = None
        app.dependency_overrides.clear()

        assert len(entries) == 1
        assert entries[0].user == "analyst1"
        assert entries[0].resource == f"scan:{scan_id}:finding:{finding['template_id']}"
