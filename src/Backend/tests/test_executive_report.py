"""Pruebas unitarias e integración de la exportación de reportes ejecutivos en PDF (HU-023).

Verifica:
- Criterio de Aceptación 1: SLA de generación < 10 s (RNF-005).
- Criterio de Aceptación 2: Inclusión de resumen ejecutivo, heatmap de severidad y top riesgos.
- Criterio de Aceptación 3: Descarga desde API protegida con autenticación MFA (RF-007 / RNF-002).
- Definition of Done: Plantilla versionada (v1.0.0) y snapshot de estructura.
"""

import time
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from atrox.config import get_settings
from atrox.main import app
from atrox.queue.models import Job, JobStatus, JobType
from atrox.reports.generator import ExecutiveReportGenerator
from atrox.reports.models import ExecutiveReportData, SeverityHeatmap, TopRiskItem, TEMPLATE_VERSION
from atrox.security.auth_deps import require_mfa_admin


@pytest.fixture
def sample_report_data():
    return ExecutiveReportData(
        scan_id=str(uuid4()),
        target="192.168.1.100",
        scan_type="vulnscan",
        generated_by="Director de TI",
        overall_risk_level="CRÍTICO",
        executive_summary="Prueba de resumen ejecutivo de alto nivel para evaluación de seguridad.",
        business_impact_narrative="Riesgo crítico de compromiso de infraestructura y fuga de datos.",
        heatmap=SeverityHeatmap(
            critical=2,
            high=4,
            medium=3,
            low=1,
            info=5,
            total=15,
            critical_pct=13.3,
            high_pct=26.7,
            medium_pct=20.0,
            low_pct=6.7,
            info_pct=33.3,
        ),
        top_risks=[
            TopRiskItem(
                rank=1,
                template_id="cve-2023-38606",
                name="Inyección de Código Remoto RCE",
                severity="CRITICAL",
                host="192.168.1.100",
                business_impact="Permite control total no autorizado sobre el servidor de producción.",
                confidence_score=95.0,
            ),
            TopRiskItem(
                rank=2,
                template_id="cve-2023-28252",
                name="Elevación de Privilegios Kernel",
                severity="HIGH",
                host="192.168.1.100",
                business_impact="Posibilita escapar del sandbox del contenedor.",
                confidence_score=88.5,
            ),
        ],
    )


class TestExecutiveReportGenerator:
    """Pruebas del motor de plantilla PDF."""

    def test_generate_pdf_structure_and_version(self, sample_report_data):
        generator = ExecutiveReportGenerator(sample_report_data)
        pdf_bytes = generator.generate()

        assert pdf_bytes is not None
        assert len(pdf_bytes) > 0
        # Cabecera estándar de archivo PDF
        assert pdf_bytes.startswith(b"%PDF-")
        assert TEMPLATE_VERSION == "1.0.0"

    def test_pdf_generation_sla_under_10_seconds(self, sample_report_data):
        """Verifica RNF-005 / Criterio de Aceptación 1: tiempo de generación < 10 s."""
        generator = ExecutiveReportGenerator(sample_report_data)
        start_time = time.perf_counter()
        pdf_bytes = generator.generate()
        elapsed = time.perf_counter() - start_time

        assert len(pdf_bytes) > 1000
        assert elapsed < 10.0, f"Generación tomó {elapsed:.3f}s, superando el SLA de 10s"

    def test_generate_empty_findings_report(self):
        """Verifica generación segura de reporte sin hallazgos."""
        data = ExecutiveReportData(
            scan_id=str(uuid4()),
            target="10.0.0.1",
            executive_summary="Sin hallazgos detectados.",
            business_impact_narrative="Riesgo bajo.",
            heatmap=SeverityHeatmap(total=0),
            top_risks=[],
        )
        generator = ExecutiveReportGenerator(data)
        pdf_bytes = generator.generate()
        assert pdf_bytes.startswith(b"%PDF-")


class TestExecutiveReportApi:
    """Pruebas de la API protegida /api/reports/executive."""

    def test_get_executive_report_unauthorized_when_mfa_active(self, monkeypatch):
        monkeypatch.setattr(get_settings(), "mfa_required", True)
        app.dependency_overrides.pop(require_mfa_admin, None)
        with TestClient(app) as client:
            scan_id = uuid4()
            response = client.get(f"/api/reports/executive/{scan_id}")
            assert response.status_code == 401

    def test_get_executive_report_not_found(self):
        app.dependency_overrides[require_mfa_admin] = lambda: {"username": "sysadmin"}
        try:
            with TestClient(app) as client:
                scan_id = uuid4()
                response = client.get(f"/api/reports/executive/{scan_id}")
                assert response.status_code == 404
                assert "no fue encontrado" in response.json()["detail"]
        finally:
            app.dependency_overrides.pop(require_mfa_admin, None)

    def test_get_executive_report_success_with_mfa_bypass_or_auth(self):
        app.dependency_overrides[require_mfa_admin] = lambda: {"username": "sysadmin"}
        try:
            with TestClient(app) as client:
                scan_id = uuid4()

                job = Job(
                    id=scan_id,
                    job_type=JobType.VULNSCAN,
                    params={"target": "192.168.1.50"},
                    status=JobStatus.DONE,
                    result={
                        "findings": [
                            {
                                "template_id": "cve-2024-1234",
                                "name": "SQL Injection Crítica",
                                "severity": "critical",
                                "host": "192.168.1.50",
                                "matched_at": "http://192.168.1.50/login",
                                "tags": ["cve", "sqli"],
                                "description": "Permite extracción arbitraria de base de datos de clientes.",
                                "references": ["https://nvd.nist.gov"],
                                "extracted_results": [],
                                "scan_type": "vulnscan",
                                "ip": "192.168.1.50",
                                "timestamp": "2026-08-04T00:00:00Z",
                            }
                        ]
                    },
                )
                app.state.job_queue._jobs[scan_id] = job

                response = client.get(
                    f"/api/reports/executive/{scan_id}",
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 200
                assert response.headers["content-type"] == "application/pdf"
                assert f"reporte_ejecutivo_{scan_id}.pdf" in response.headers["content-disposition"]
                assert response.headers.get("X-Report-Template-Version") == "1.0.0"
                assert response.content.startswith(b"%PDF-")
        finally:
            app.dependency_overrides.pop(require_mfa_admin, None)

    def test_post_custom_executive_report(self, sample_report_data):
        app.dependency_overrides[require_mfa_admin] = lambda: {"username": "sysadmin"}
        try:
            with TestClient(app) as client:
                payload = sample_report_data.model_dump()
                response = client.post(
                    "/api/reports/executive",
                    json=payload,
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 200
                assert response.headers["content-type"] == "application/pdf"
                assert response.content.startswith(b"%PDF-")
        finally:
            app.dependency_overrides.pop(require_mfa_admin, None)
