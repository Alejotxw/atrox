"""Integración HU-007: cifrado en endpoints, jobs y persistencia."""

import base64
import os
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from atrox.main import app
from atrox.persistence.models import CredentialCreate, FindingCreate, ReportCreate
from atrox.persistence.service import EncryptedPersistenceService
from atrox.persistence.store import JsonEntityStore
from atrox.security.encryption import generate_master_key, get_encryption_service
from atrox.security.sensitive_fields import SensitiveFieldEncryptor


@pytest.fixture
def encryptor() -> SensitiveFieldEncryptor:
    return SensitiveFieldEncryptor(get_encryption_service(generate_master_key()))


@pytest.fixture
def persistence(tmp_path: Path, encryptor: SensitiveFieldEncryptor) -> EncryptedPersistenceService:
    return EncryptedPersistenceService(
        encryptor=encryptor,
        findings_store=JsonEntityStore(tmp_path / "findings.jsonl"),
        credentials_store=JsonEntityStore(tmp_path / "credentials.jsonl"),
        reports_store=JsonEntityStore(tmp_path / "reports.jsonl"),
    )


@pytest.fixture
def client_with_persistence(persistence: EncryptedPersistenceService):
    app.state.persistence = persistence
    yield TestClient(app)
    app.state.persistence = None


def test_finding_persisted_encrypted_at_rest(persistence: EncryptedPersistenceService) -> None:
    import asyncio

    saved = asyncio.run(
        persistence.save_finding(
            FindingCreate(
                name="SQL Injection",
                severity="critical",
                description="Blind SQLi evidence",
                evidence="' OR 1=1 --",
                poc="POST /login.php",
            )
        )
    )

    assert saved.description == "Blind SQLi evidence"

    raw = persistence.findings_store.read_raw_lines()
    assert len(raw) == 1
    assert "Blind SQLi evidence" not in raw[0]
    assert "OR 1=1" not in raw[0]
    assert "AES-256-GCM" in raw[0]


def test_credential_persisted_encrypted_at_rest(persistence: EncryptedPersistenceService) -> None:
    import asyncio

    saved = asyncio.run(
        persistence.save_credential(
            CredentialCreate(
                username="admin",
                host="10.0.0.5",
                password="SuperSecret123!",
                token="tok-abc-xyz",
            )
        )
    )

    assert saved.password == "SuperSecret123!"

    raw = persistence.credentials_store.read_raw_lines()[0]
    assert "SuperSecret123!" not in raw
    assert "tok-abc-xyz" not in raw
    assert "AES-256-GCM" in raw


def test_report_persisted_encrypted_at_rest(persistence: EncryptedPersistenceService) -> None:
    import asyncio

    saved = asyncio.run(
        persistence.save_report(
            ReportCreate(
                title="Reporte Q2",
                content="Hallazgos confidenciales del cliente",
                executive_summary="Riesgo alto en login",
            )
        )
    )

    assert "confidenciales" in saved.content

    raw = persistence.reports_store.read_raw_lines()[0]
    assert "confidenciales" not in raw
    assert "Riesgo alto" not in raw


def test_api_create_and_list_finding(client_with_persistence: TestClient) -> None:
    response = client_with_persistence.post(
        "/api/findings",
        json={
            "name": "Path Traversal",
            "severity": "critical",
            "description": "Lee /etc/passwd",
            "evidence": "root:x:0:0",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["description"] == "Lee /etc/passwd"

    listed = client_with_persistence.get("/api/findings")
    assert listed.status_code == 200
    assert len(listed.json()) >= 1


def test_api_create_credential_and_report(client_with_persistence: TestClient) -> None:
    cred = client_with_persistence.post(
        "/api/credentials",
        json={"username": "root", "password": "toor", "host": "db.local"},
    )
    assert cred.status_code == 201
    assert cred.json()["password"] == "toor"

    report = client_with_persistence.post(
        "/api/reports",
        json={
            "title": "Ejecutivo",
            "report_type": "executive",
            "executive_summary": "3 vulnerabilidades críticas",
            "body": "Detalle técnico confidencial",
        },
    )
    assert report.status_code == 201
    assert "críticas" in report.json()["executive_summary"]


def test_api_unavailable_without_persistence() -> None:
    app.state.persistence = None
    client = TestClient(app)
    response = client.get("/api/findings")
    assert response.status_code == 503


def test_encrypt_job_result_roundtrip(persistence: EncryptedPersistenceService) -> None:
    result = {
        "target": "lab.local",
        "findings": [
            {
                "template_id": "sqli",
                "name": "SQLi",
                "severity": "critical",
                "description": "payload sensible",
                "extracted_results": ["secret-row"],
                "matched_at": "http://lab.local/login",
            }
        ],
    }

    encrypted = persistence.encrypt_job_result(result)
    finding = encrypted["findings"][0]
    assert isinstance(finding["description"], dict)
    assert finding["description"]["alg"] == "AES-256-GCM"
    assert "payload sensible" not in str(finding["description"])

    decrypted = persistence.decrypt_job_result(encrypted)
    assert decrypted["findings"][0]["description"] == "payload sensible"
    assert "secret-row" in decrypted["findings"][0]["evidence"]


def test_cannot_read_persisted_finding_without_valid_key(
    tmp_path: Path,
) -> None:
    import asyncio

    key_a = generate_master_key()
    key_b = generate_master_key()

    store_a = EncryptedPersistenceService(
        encryptor=SensitiveFieldEncryptor(get_encryption_service(key_a)),
        findings_store=JsonEntityStore(tmp_path / "findings.jsonl"),
        credentials_store=JsonEntityStore(tmp_path / "credentials.jsonl"),
        reports_store=JsonEntityStore(tmp_path / "reports.jsonl"),
    )
    finding_id = asyncio.run(
        store_a.save_finding(
            FindingCreate(name="X", description="dato-secreto", evidence="poc")
        )
    ).id

    store_b = EncryptedPersistenceService(
        encryptor=SensitiveFieldEncryptor(get_encryption_service(key_b)),
        findings_store=JsonEntityStore(tmp_path / "findings.jsonl"),
        credentials_store=JsonEntityStore(tmp_path / "credentials.jsonl"),
        reports_store=JsonEntityStore(tmp_path / "reports.jsonl"),
    )

    from atrox.security.encryption import DecryptionError

    with pytest.raises(DecryptionError):
        asyncio.run(store_b.get_finding(finding_id, decrypt=True))
