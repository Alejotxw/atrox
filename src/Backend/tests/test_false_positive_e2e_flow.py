"""Test E2E (a nivel API, sin navegador) del flujo completo de HU-022.

Recorre el ciclo real de extremo a extremo tal como lo ejecutaría un
SysAdmin desde la UI: crear un escaneo, ver el hallazgo listado (HU-010),
marcarlo como falso positivo (HU-022), confirmar que queda excluido por
defecto, que sigue disponible como dataset etiquetado (DoD), y que quedó
un evento firmado en el log de auditoría (HU-008).

No hay tooling de E2E de navegador en el proyecto (ni Playwright ni
Cypress, ver README del frontend) — este es "E2E" en el sentido de
recorrer la pila real del backend de punta a punta vía `TestClient`, no una
automatización de UI. Decisión acordada explícitamente: no se instaló
tooling de navegador para esta HU.
"""

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


@pytest.fixture
def e2e_client(tmp_path: Path):
    queue = JobQueue(max_concurrent=2, max_queue_size=10)
    fp_store = FalsePositiveStore(store_path=tmp_path / "false_positives.jsonl")

    signing_key = generate_signing_key()
    audit_store = AuditLogStore(tmp_path / "audit.log", retention_days=30)
    audit_service = AuditLogService(store=audit_store, signer=AuditSigner(decode_signing_key(signing_key)))

    app.dependency_overrides[get_job_queue] = lambda: queue
    app.dependency_overrides[get_false_positive_store] = lambda: fp_store
    app.state.audit_log = audit_service

    yield TestClient(app), queue, audit_service

    app.state.audit_log = None
    app.dependency_overrides.clear()


def test_full_manual_false_positive_flow(e2e_client) -> None:
    client, queue, audit_service = e2e_client

    # 1. El SysAdmin crea un escaneo (HU-009) — encolado automáticamente en HU-004.
    create_resp = client.post("/api/scans", json={"target": "example.com", "scan_type": "vulnscan"})
    assert create_resp.status_code == 202
    scan_id = create_resp.json()["scan_id"]

    # El escaneo "termina" con dos hallazgos (se inyecta el resultado
    # directamente en la cola en vez de invocar Nuclei real — mismo patrón
    # usado en los tests de HU-010).
    finding_to_mark = {
        "template_id": "cve-generic-banner-match",
        "name": "CVE Banner Match (Generic)",
        "severity": "high",
        "host": "http://example.com",
        "matched_at": "http://example.com/",
        "tags": ["cve", "tech"],
        "description": "Coincidencia automática por banner genérico; alto historial de FP.",
        "extracted_results": ["Server: nginx/1.18.0"],
    }
    other_finding = {
        "template_id": "cve-2021-41773",
        "name": "Apache Path Traversal",
        "severity": "critical",
        "host": "http://example.com",
        "matched_at": "http://example.com/traversal",
        "tags": ["cve", "rce"],
        "extracted_results": ["root:x:0:0:root:/root:/bin/bash"],
    }
    job = queue.get_job(UUID(scan_id))
    job.transition_to(JobStatus.RUNNING)
    job.result = {
        "target": "example.com",
        "status": "completed",
        "findings": [finding_to_mark, other_finding],
    }
    job.transition_to(JobStatus.DONE)

    # 2. El analista consulta los hallazgos vía HU-010 — ambos aparecen.
    detail_before = client.get(f"/api/scans/{scan_id}")
    assert detail_before.status_code == 200
    assert detail_before.json()["findings"]["total"] == 2

    # 3. El SysAdmin marca el hallazgo ruidoso como falso positivo desde la UI.
    mark_resp = client.post(
        f"/api/scans/{scan_id}/findings/false-positive",
        json={"finding": finding_to_mark, "reason": "Banner grab genérico, no explotable"},
        headers={"X-Atrox-User": "sysadmin.rivera"},
    )
    assert mark_resp.status_code == 201
    mark_body = mark_resp.json()

    # AC: la acción persiste estado false_positive con usuario y timestamp.
    assert mark_body["user"] == "sysadmin.rivera"
    assert mark_body["marked_at"] is not None
    assert mark_body["finding_id"] == "cve-generic-banner-match"

    # 4. AC: el hallazgo queda excluido de HU-010 (reportes) por defecto.
    detail_after = client.get(f"/api/scans/{scan_id}")
    assert detail_after.status_code == 200
    remaining = detail_after.json()["findings"]["items"]
    assert len(remaining) == 1
    assert remaining[0]["template_id"] == "cve-2021-41773"

    # ...pero sigue siendo consultable explícitamente si se necesita.
    detail_with_fp = client.get(f"/api/scans/{scan_id}", params={"include_false_positives": "true"})
    assert detail_with_fp.json()["findings"]["total"] == 2

    # 5. DoD: el dato queda disponible para reentrenamiento/heurística futura.
    dataset_resp = client.get(f"/api/scans/{scan_id}/findings/false-positives")
    assert dataset_resp.status_code == 200
    dataset = dataset_resp.json()
    assert len(dataset) == 1
    assert dataset[0]["finding"]["severity"] == "high"
    assert dataset[0]["finding"]["tags"] == ["cve", "tech"]
    assert dataset[0]["user"] == "sysadmin.rivera"

    # 6. AC: evento registrado en el log de auditoría inmutable de HU-008.
    entries, verified, tampered = asyncio.run(
        audit_service.query(action="finding.marked_false_positive")
    )
    assert len(entries) == 1
    assert entries[0].user == "sysadmin.rivera"
    assert entries[0].resource == f"scan:{scan_id}:finding:cve-generic-banner-match"
    assert verified == 1
    assert tampered == 0

    integrity = client.get("/api/audit/integrity")
    assert integrity.json()["valid"] is True
