"""
Tests del agente de vectores de ataque (HU-014).

Caso validado manualmente (Red Team / laboratorio):
  Vector 1: SQLi web → MySQL default creds (2 hallazgos encadenados)
  Vector 2: Path traversal Apache → Auth bypass Confluence (2 hallazgos encadenados)
"""

import time

import pytest
from fastapi.testclient import TestClient

from atrox.ai.agents.vectors.analyzer import (
    VectorAnalysisAgent,
    MAX_BATCH_SIZE,
    SLA_MS,
    prioritize_findings,
)
from atrox.api.vectors import get_vector_agent
from atrox.main import app
from atrox.scanner.models import VulnFinding, VulnSeverity

# ── Hallazgos simulados HU-003 (Nuclei) — escenario laboratorio ─────────────

SQL_INJECTION = VulnFinding(
    template_id="sqli-login-blind",
    name="SQL Injection (Blind)",
    severity=VulnSeverity.CRITICAL,
    host="http://lab.local",
    matched_at="http://lab.local/login.php?user=admin",
    tags=["sqli", "injection", "web"],
    description="Blind SQL injection in login form parameter 'user'",
    ip="192.168.1.10",
)

MYSQL_DEFAULT = VulnFinding(
    template_id="mysql-default-credentials",
    name="MySQL Default Credentials",
    severity=VulnSeverity.HIGH,
    host="mysql://192.168.1.10:3306",
    matched_at="192.168.1.10:3306",
    tags=["mysql", "database", "default-login"],
    description="MySQL accepts root/root on port 3306",
    ip="192.168.1.10",
)

PATH_TRAVERSAL = VulnFinding(
    template_id="cve-2021-41773",
    name="Apache HTTP Server Path Traversal",
    severity=VulnSeverity.CRITICAL,
    host="http://192.168.1.10:80",
    matched_at="http://192.168.1.10:80/cgi-bin/.%2e/.%2e/etc/passwd",
    tags=["cve", "apache", "traversal", "lfi"],
    description="Apache 2.4.49 path traversal allows arbitrary file read",
    ip="192.168.1.10",
)

AUTH_BYPASS = VulnFinding(
    template_id="cve-2023-22515",
    name="Confluence Auth Bypass",
    severity=VulnSeverity.HIGH,
    host="http://192.168.1.10:8090",
    matched_at="http://192.168.1.10:8090/setup/setupadministrator.action",
    tags=["cve", "confluence", "auth-bypass", "auth"],
    description="Broken access control allows admin account creation",
    ip="192.168.1.10",
)

LAB_FINDINGS = [SQL_INJECTION, MYSQL_DEFAULT, PATH_TRAVERSAL, AUTH_BYPASS]


@pytest.fixture
def agent() -> VectorAnalysisAgent:
    return VectorAnalysisAgent()


def test_two_chained_vectors_validated_manually(agent: VectorAnalysisAgent) -> None:
    """
    DoD: al menos 2 vectores encadenados validados manualmente.

    Vector 1 (web-sqli-to-db): sqli-login-blind + mysql-default-credentials
    Vector 2 (path-traversal-to-rce): cve-2021-41773 + cve-2023-22515
    """
    result = agent.analyze(LAB_FINDINGS)

    chained = [v for v in result.vectors if len(v.finding_ids) >= 2 and len(v.chain) >= 3]
    assert len(chained) >= 2, f"Se esperaban ≥2 vectores encadenados, got {len(chained)}"

    finding_sets = {frozenset(v.finding_ids) for v in chained}
    assert frozenset({"sqli-login-blind", "mysql-default-credentials"}) in finding_sets
    assert frozenset({"cve-2021-41773", "cve-2023-22515"}) in finding_sets

    for vector in chained:
        assert vector.justification
        assert vector.estimated_impact
        assert vector.rank >= 1


def test_vectors_ordered_by_impact(agent: VectorAnalysisAgent) -> None:
    result = agent.analyze(LAB_FINDINGS)

    scores = [v.severity_score for v in result.vectors]
    assert scores == sorted(scores, reverse=True)

    ranks = [v.rank for v in result.vectors]
    assert ranks == list(range(1, len(result.vectors) + 1))


def test_prioritize_findings_puts_critical_first() -> None:
    low = VulnFinding(
        template_id="low-1",
        name="Low",
        severity=VulnSeverity.LOW,
        host="http://a",
        matched_at="http://a/",
    )
    critical = VulnFinding(
        template_id="crit-1",
        name="Crit",
        severity=VulnSeverity.CRITICAL,
        host="http://b",
        matched_at="http://b/",
    )
    info = VulnFinding(
        template_id="info-1",
        name="Info",
        severity=VulnSeverity.INFO,
        host="http://c",
        matched_at="http://c/",
    )
    ordered = prioritize_findings([low, info, critical], limit=2)
    assert [f.template_id for f in ordered] == ["crit-1", "low-1"]


def test_response_under_5_seconds_for_10_findings(agent: VectorAnalysisAgent) -> None:
    batch = [
        VulnFinding(
            template_id=f"finding-{i:03d}",
            name=f"Test Vuln {i}",
            severity=VulnSeverity.HIGH if i % 2 == 0 else VulnSeverity.MEDIUM,
            host=f"http://host{i}.local",
            matched_at=f"http://host{i}.local/vuln",
            tags=["web", "sqli"] if i < 3 else ["database", "mysql"],
            ip="10.0.0.1",
        )
        for i in range(MAX_BATCH_SIZE)
    ]

    start = time.perf_counter()
    result = agent.analyze(batch)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert result.total_findings == MAX_BATCH_SIZE
    assert result.within_sla is True
    assert result.analysis_time_ms < SLA_MS
    assert elapsed_ms < SLA_MS


def test_empty_findings_returns_empty_vectors(agent: VectorAnalysisAgent) -> None:
    result = agent.analyze([])
    assert result.vectors == []
    assert result.total_findings == 0
    assert result.within_sla is True


def test_each_vector_has_justification(agent: VectorAnalysisAgent) -> None:
    result = agent.analyze(LAB_FINDINGS)
    for vector in result.vectors:
        assert len(vector.justification) > 20
        assert vector.name
        assert vector.chain


def test_api_analyze_vectors() -> None:
    """DoD del motor heurístico vía API — aislado del LLM real configurado en
    el entorno local (.env puede tener ATROX_LLM_PROVIDER=ollama)."""
    app.dependency_overrides[get_vector_agent] = lambda: VectorAnalysisAgent()
    client = TestClient(app)
    payload = {
        "findings": [f.model_dump(mode="json") for f in LAB_FINDINGS],
    }

    try:
        response = client.post("/api/ai/vectors/analyze", json=payload)
    finally:
        app.dependency_overrides.pop(get_vector_agent, None)

    assert response.status_code == 200
    body = response.json()
    assert body["total_findings"] == 4
    assert body["source"] == "heuristic"
    assert body["within_sla"] is True
    assert len(body["vectors"]) >= 2

    chained = [v for v in body["vectors"] if len(v["finding_ids"]) >= 2]
    assert len(chained) >= 2


def test_api_rejects_more_than_10_findings() -> None:
    client = TestClient(app)
    findings = [
        {
            "template_id": f"f-{i}",
            "name": f"Vuln {i}",
            "severity": "medium",
            "host": "http://x.local",
            "matched_at": "http://x.local/",
        }
        for i in range(11)
    ]

    response = client.post("/api/ai/vectors/analyze", json={"findings": findings})
    assert response.status_code == 422
