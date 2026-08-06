import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from atrox.main import app
from atrox.security.audit_models import TamperDetectedError
from atrox.security.audit_service import AuditLogService, AuditLogStore
from atrox.security.audit_signer import AuditSigner, AuditSignatureError, decode_signing_key, generate_signing_key


@pytest.fixture
def signing_key_b64() -> str:
    return generate_signing_key()


@pytest.fixture
def audit_service(tmp_path: Path, signing_key_b64: str) -> AuditLogService:
    store = AuditLogStore(tmp_path / "audit.log", retention_days=30)
    signer = AuditSigner(decode_signing_key(signing_key_b64))
    return AuditLogService(store=store, signer=signer)


@pytest.fixture
def client_with_audit(audit_service: AuditLogService) -> TestClient:
    app.state.audit_log = audit_service
    c = TestClient(app)
    c.headers["Authorization"] = "Bearer test-audit-token"
    yield c
    app.state.audit_log = None


def test_record_includes_timestamp_user_action_resource(
    audit_service: AuditLogService,
) -> None:
    entry = asyncio.run(
        audit_service.record(
            user="director.ti",
            action="policy.updated",
            resource="policy:scheduling",
            metadata={"cron": "0 2 * * *"},
        )
    )

    assert entry.user == "director.ti"
    assert entry.action == "policy.updated"
    assert entry.resource == "policy:scheduling"
    assert entry.timestamp is not None
    assert entry.signature
    assert audit_service._signer.verify(entry.model_dump(mode="json"))


def test_tamper_detection_on_modified_entry(audit_service: AuditLogService) -> None:
    entry = asyncio.run(
        audit_service.record(
            user="sysadmin",
            action="scan.started",
            resource="job:abc-123",
        )
    )

    raw_entries = asyncio.run(audit_service._store.read_all())
    tampered = dict(raw_entries[0])
    tampered["action"] = "scan.deleted"

    assert audit_service._signer.verify(tampered) is False

    tampered_ids = asyncio.run(audit_service.verify_integrity())
    assert str(entry.id) not in tampered_ids

    asyncio.run(audit_service._store.rewrite([tampered]))
    tampered_ids = asyncio.run(audit_service.verify_integrity())
    assert str(entry.id) in tampered_ids


def test_verify_integrity_or_raise(audit_service: AuditLogService) -> None:
    asyncio.run(audit_service.record(user="u1", action="scan.submitted", resource="job:1"))

    raw = asyncio.run(audit_service._store.read_all())
    raw[0]["user"] = "attacker"
    asyncio.run(audit_service._store.rewrite(raw))

    with pytest.raises(TamperDetectedError):
        asyncio.run(audit_service.verify_integrity_or_raise())


def test_query_filters_by_date_range(audit_service: AuditLogService) -> None:
    old_ts = datetime.now(UTC) - timedelta(days=10)
    recent_ts = datetime.now(UTC) - timedelta(hours=1)

    asyncio.run(audit_service.record(user="u1", action="scan.submitted", resource="job:old"))
    asyncio.run(audit_service.record(user="u1", action="scan.submitted", resource="job:new"))

    raw = asyncio.run(audit_service._store.read_all())
    raw[0]["timestamp"] = old_ts.isoformat()
    raw[1]["timestamp"] = recent_ts.isoformat()
    for entry in raw:
        entry["signature"] = audit_service._signer.sign(
            {k: v for k, v in entry.items() if k != "signature"}
        )
    asyncio.run(audit_service._store.rewrite(raw))

    from_date = datetime.now(UTC) - timedelta(days=2)
    entries, verified, tampered = asyncio.run(audit_service.query(from_date=from_date))

    assert len(entries) == 1
    assert entries[0].resource == "job:new"
    assert verified == 1
    assert tampered == 0


def test_retention_purges_old_entries(audit_service: AuditLogService) -> None:
    asyncio.run(audit_service.record(user="u1", action="scan.submitted", resource="job:old"))

    raw = asyncio.run(audit_service._store.read_all())
    old_ts = datetime.now(UTC) - timedelta(days=60)
    raw[0]["timestamp"] = old_ts.isoformat()
    raw[0]["signature"] = audit_service._signer.sign(
        {k: v for k, v in raw[0].items() if k != "signature"}
    )
    asyncio.run(audit_service._store.rewrite(raw))

    removed = asyncio.run(audit_service.purge_expired())
    assert removed == 1
    assert asyncio.run(audit_service._store.read_all()) == []


def test_audit_logs_api_returns_filtered_entries(client_with_audit: TestClient) -> None:
    create = client_with_audit.post(
        "/api/audit/events",
        json={
            "user": "director.ti",
            "action": "policy.updated",
            "resource": "policy:retention",
            "metadata": {"days": 90},
        },
    )
    assert create.status_code == 201

    response = client_with_audit.get(
        "/api/audit/logs",
        params={"user": "director.ti", "action": "policy.updated"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["tampered"] == 0
    assert body["entries"][0]["user"] == "director.ti"
    assert body["entries"][0]["action"] == "policy.updated"


def test_integrity_endpoint_detects_tampering(
    client_with_audit: TestClient,
    audit_service: AuditLogService,
) -> None:
    client_with_audit.post(
        "/api/audit/events",
        json={"user": "u1", "action": "scan.submitted", "resource": "job:1"},
    )

    raw = asyncio.run(audit_service._store.read_all())
    raw[0]["resource"] = "job:tampered"
    asyncio.run(audit_service._store.rewrite(raw))

    response = client_with_audit.get("/api/audit/integrity")
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert body["tampered_count"] == 1


def test_audit_api_unavailable_without_config() -> None:
    app.state.audit_log = None
    client = TestClient(app)

    response = client.get("/api/audit/logs", headers={"Authorization": "Bearer test-audit-token"})
    assert response.status_code == 503

    app.state.audit_log = None


def test_signer_rejects_invalid_signature() -> None:
    signer = AuditSigner(decode_signing_key(generate_signing_key()))
    entry = {"id": "1", "user": "u", "action": "a", "resource": "r", "signature": "invalid"}

    with pytest.raises(AuditSignatureError):
        signer.verify_or_raise(entry)
