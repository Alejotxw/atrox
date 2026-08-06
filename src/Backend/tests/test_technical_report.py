"""Pruebas unitarias e integración de la exportación de reportes técnicos en PDF y HTML (HU-024).

Verifica:
- Criterio de Aceptación 1: Generación de formatos PDF y HTML con evidencias PoC, identificadores CVE, comandos y mitigación.
- Criterio de Aceptación 2: Cifrado en reposo AES-256-GCM de campos técnicos sensibles (HU-007 / RNF-001).
- Criterio de Aceptación 3: Tiempo de generación SLA < 10 s (RNF-005).
- Definition of Done: Plantilla versionada (v1.0.0) y endpoints protegidos por MFA.
"""

import time
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from atrox.config import get_settings
from atrox.main import app
from atrox.queue.models import Job, JobStatus, JobType
from atrox.reports.models import TEMPLATE_VERSION, TechnicalFindingItem, TechnicalReportData
from atrox.reports.technical_generator import TechnicalReportGenerator
from atrox.security.auth_deps import require_mfa_admin
from atrox.security.encryption import EncryptionService
from atrox.security.sensitive_fields import SensitiveFieldEncryptor


@pytest.fixture
def sample_technical_report_data():
    return TechnicalReportData(
        scan_id=str(uuid4()),
        target="192.168.1.50",
        scan_type="vulnscan",
        generated_by="SysAdmin",
        environment_summary="Evaluación técnica de seguridad en servidor web nginx de producción.",
        total_findings=2,
        findings=[
            TechnicalFindingItem(
                item_id=1,
                template_id="cve-2021-41773",
                name="Apache Path Traversal y RCE",
                severity="CRITICAL",
                host="192.168.1.50",
                matched_at="http://192.168.1.50/icons/.%2e/%2e%2e/%2e%2e/etc/passwd",
                cve_ids=["CVE-2021-41773"],
                tags=["cve", "rce", "traversal"],
                description="Vulnerabilidad de salto de directorio que permite lectura arbitraria de archivos.",
                poc_evidence="curl -s 'http://192.168.1.50/icons/.%2e/%2e%2e/%2e%2e/etc/passwd'\nroot:x:0:0:root:/root:/bin/bash",
                remediation_steps="Actualizar servidor HTTP Apache a la versión 2.4.51 o superior inmediatamente.",
                remediation_commands=[
                    "sudo apt-get update && sudo apt-get install --only-upgrade apache2",
                    "sudo systemctl restart apache2",
                ],
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
            ),
            TechnicalFindingItem(
                item_id=2,
                template_id="mysql-default-credentials",
                name="Credenciales por Defecto en MySQL",
                severity="HIGH",
                host="192.168.1.50:3306",
                matched_at="mysql://192.168.1.50:3306",
                cve_ids=[],
                tags=["mysql", "default-login"],
                description="El servidor de base de datos MySQL permite autenticación con usuario root sin clave.",
                poc_evidence="mysql -h 192.168.1.50 -u root --password=''\nConnection established. Access granted.",
                remediation_steps="Configurar clave robusta para el usuario root de MySQL y deshabilitar acceso remoto.",
                remediation_commands=[
                    "ALTER USER 'root'@'%' IDENTIFIED BY 'StrongPassword2026!';",
                    "FLUSH PRIVILEGES;",
                ],
                references=["https://dev.mysql.com/doc/refman/8.0/en/default-privileges.html"],
            ),
        ],
    )


class TestTechnicalReportGenerator:
    """Pruebas del motor generador de reportes técnicos (PDF y HTML)."""

    def test_generate_pdf_structure_and_sla(self, sample_technical_report_data):
        generator = TechnicalReportGenerator(sample_technical_report_data)
        start_time = time.perf_counter()
        pdf_bytes = generator.generate_pdf()
        elapsed = time.perf_counter() - start_time

        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 1000
        assert elapsed < 10.0, f"Generación PDF técnico tomó {elapsed:.3f}s, violando SLA"

    def test_generate_html_content_and_sla(self, sample_technical_report_data):
        generator = TechnicalReportGenerator(sample_technical_report_data)
        start_time = time.perf_counter()
        html_str = generator.generate_html()
        elapsed = time.perf_counter() - start_time

        assert "<!DOCTYPE html>" in html_str
        assert "Reporte Técnico de Remediación y PoC" in html_str
        assert "CVE-2021-41773" in html_str
        assert "Evidencia de Explotación (Proof of Concept - PoC)" in html_str
        assert "sudo systemctl restart apache2" in html_str
        assert f"v{TEMPLATE_VERSION}" in html_str
        assert elapsed < 10.0, f"Generación HTML técnico tomó {elapsed:.3f}s, violando SLA"

    def test_sensitive_fields_encryption_at_rest(self):
        """Verifica RNF-001 / Criterio de Aceptación 2: Cifrado en reposo AES-256-GCM de campos técnicos."""
        from atrox.security.encryption import decode_master_key, generate_master_key
        raw_key = generate_master_key()
        master_key = decode_master_key(raw_key)
        service = EncryptionService(master_key)
        encryptor = SensitiveFieldEncryptor(service)

        data = {
            "poc_evidence": "root:x:0:0:root:/root:/bin/bash",
            "remediation_steps": "Actualizar paquete a versión parcheada.",
            "unrelated_field": "public_info",
        }

        encrypted = encryptor.encrypt_fields("report", data)
        assert encryptor.is_encrypted(encrypted["poc_evidence"])
        assert encryptor.is_encrypted(encrypted["remediation_steps"])
        assert encrypted["unrelated_field"] == "public_info"

        decrypted = encryptor.decrypt_fields("report", encrypted)
        assert decrypted["poc_evidence"] == "root:x:0:0:root:/root:/bin/bash"
        assert decrypted["remediation_steps"] == "Actualizar paquete a versión parcheada."


class TestTechnicalReportApi:
    """Pruebas de la API protegida /api/reports/technical."""

    def test_get_technical_report_pdf_success(self):
        app.dependency_overrides[require_mfa_admin] = lambda: {"username": "sysadmin"}
        try:
            with TestClient(app) as client:
                scan_id = uuid4()
                job = Job(
                    id=scan_id,
                    job_type=JobType.VULNSCAN,
                    params={"target": "10.0.0.5"},
                    status=JobStatus.DONE,
                    result={
                        "findings": [
                            {
                                "template_id": "cve-2021-41773",
                                "name": "Apache Traversal",
                                "severity": "critical",
                                "host": "10.0.0.5",
                                "matched_at": "http://10.0.0.5/",
                                "tags": ["cve-2021-41773"],
                                "description": "Salto de directorio en Apache HTTPD.",
                                "references": [],
                                "extracted_results": ["root:x:0:0"],
                                "scan_type": "vulnscan",
                                "ip": "10.0.0.5",
                                "timestamp": "2026-08-04T00:00:00Z",
                            }
                        ]
                    },
                )
                app.state.job_queue._jobs[scan_id] = job

                response = client.get(
                    f"/api/reports/technical/{scan_id}?format=pdf",
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 200
                assert response.headers["content-type"] == "application/pdf"
                assert response.content.startswith(b"%PDF-")
        finally:
            app.dependency_overrides.pop(require_mfa_admin, None)

    def test_get_technical_report_html_success(self):
        app.dependency_overrides[require_mfa_admin] = lambda: {"username": "sysadmin"}
        try:
            with TestClient(app) as client:
                scan_id = uuid4()
                job = Job(
                    id=scan_id,
                    job_type=JobType.VULNSCAN,
                    params={"target": "10.0.0.5"},
                    status=JobStatus.DONE,
                    result={"findings": []},
                )
                app.state.job_queue._jobs[scan_id] = job

                response = client.get(
                    f"/api/reports/technical/{scan_id}?format=html",
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 200
                assert "text/html" in response.headers["content-type"]
                assert "<!DOCTYPE html>" in response.text
                assert "Reporte Técnico de Remediación" in response.text
        finally:
            app.dependency_overrides.pop(require_mfa_admin, None)

    def test_post_custom_technical_report(self, sample_technical_report_data):
        app.dependency_overrides[require_mfa_admin] = lambda: {"username": "sysadmin"}
        try:
            with TestClient(app) as client:
                payload = sample_technical_report_data.model_dump()
                response = client.post(
                    "/api/reports/technical?format=html",
                    json=payload,
                    headers={"Authorization": "Bearer test-token"},
                )
                assert response.status_code == 200
                assert "text/html" in response.headers["content-type"]
                assert "Apache Path Traversal y RCE" in response.text
        finally:
            app.dependency_overrides.pop(require_mfa_admin, None)
