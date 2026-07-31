"""Tests unitarios para el router /api/threats (HU-005)."""

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from atrox.api.threats import get_nvd_sync_service
from atrox.main import app
from atrox.threat_intel.cve_store import CveStore
from atrox.threat_intel.models import CVEEntry
from atrox.threat_intel.service import NvdSyncService
from tests.fixtures.nvd_fakes import FakeNvdClient


def _make_cve(cve_id: str, severity: str = "CRITICAL", desc: str = "desc") -> CVEEntry:
    return CVEEntry(
        cve_id=cve_id,
        description=desc,
        cvss_score=9.8,
        cvss_severity=severity,
        published_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


@pytest.fixture
def threats_client(tmp_path: Path):
    """TestClient con DI override del servicio NVD (almacén fresco por test)."""
    store = CveStore(
        store_path=tmp_path / "cves.jsonl",
        sync_status_path=tmp_path / "last_sync.json",
    )
    client = FakeNvdClient(
        entries=[
            _make_cve("CVE-2021-44228", "CRITICAL", desc="Log4j RCE"),
            _make_cve("CVE-2022-0002", "HIGH", desc="OpenSSL overflow"),
        ]
    )
    service = NvdSyncService(client=client, store=store)
    app.dependency_overrides[get_nvd_sync_service] = lambda: service
    yield TestClient(app), service
    app.dependency_overrides.clear()


class TestPostSync:
    """Scenario: Sincronización manual disparada por API (DoD)."""

    def test_post_sync_returns_202_with_status(self, threats_client) -> None:
        client, _ = threats_client

        response = client.post("/api/threats/sync")

        assert response.status_code == 202
        body = response.json()
        assert body["status"] == "ok"
        assert body["cves_added"] == 2
        assert body["cves_total"] == 2

    def test_post_sync_indexes_catalog_available_for_queries(self, threats_client) -> None:
        client, _ = threats_client

        client.post("/api/threats/sync")
        response = client.get("/api/threats/cves")

        assert response.status_code == 200
        assert response.json()["total"] == 2


class TestLastSync:
    """Scenario: Log de última sincronización consultable (DoD)."""

    def test_last_sync_before_any_run(self, threats_client) -> None:
        client, _ = threats_client

        response = client.get("/api/threats/last-sync")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "error"
        assert "no se ha ejecutado" in body["last_error"]

    def test_last_sync_after_run(self, threats_client) -> None:
        client, _ = threats_client

        client.post("/api/threats/sync")
        response = client.get("/api/threats/last-sync")

        body = response.json()
        assert body["status"] == "ok"
        assert body["last_success_at"] is not None
        assert body["cves_total"] == 2


class TestListCves:
    """Scenario: Consultar el catálogo indexado (RF-010 correlación)."""

    def test_list_cves_returns_paginated_catalog(self, threats_client) -> None:
        client, _ = threats_client
        client.post("/api/threats/sync")

        response = client.get("/api/threats/cves")

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 2
        assert body["page"] == 1
        assert body["total_pages"] == 1
        assert len(body["items"]) == 2

    def test_list_cves_filters_by_severity(self, threats_client) -> None:
        client, _ = threats_client
        client.post("/api/threats/sync")

        response = client.get("/api/threats/cves", params={"severity": "high"})

        assert response.json()["total"] == 1
        assert response.json()["items"][0]["cve_id"] == "CVE-2022-0002"

    def test_list_cves_filters_by_cve_id_substring(self, threats_client) -> None:
        client, _ = threats_client
        client.post("/api/threats/sync")

        response = client.get("/api/threats/cves", params={"cve_id": "CVE-2021"})

        assert response.json()["total"] == 1
        assert response.json()["items"][0]["cve_id"] == "CVE-2021-44228"

    def test_list_cves_searches_description(self, threats_client) -> None:
        client, _ = threats_client
        client.post("/api/threats/sync")

        response = client.get("/api/threats/cves", params={"q": "openssl"})

        assert response.json()["total"] == 1
        assert response.json()["items"][0]["cve_id"] == "CVE-2022-0002"


class TestGetCve:
    """Scenario: Consultar un CVE individual del catálogo."""

    def test_get_cve_returns_entry(self, threats_client) -> None:
        client, _ = threats_client
        client.post("/api/threats/sync")

        response = client.get("/api/threats/cves/CVE-2021-44228")

        assert response.status_code == 200
        body = response.json()
        assert body["cve_id"] == "CVE-2021-44228"
        assert body["cvss_severity"] == "CRITICAL"

    def test_get_unknown_cve_returns_404(self, threats_client) -> None:
        client, _ = threats_client

        response = client.get("/api/threats/cves/CVE-9999-9999")

        assert response.status_code == 404
