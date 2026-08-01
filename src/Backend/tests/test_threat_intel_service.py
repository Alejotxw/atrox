"""Tests unitarios para el servicio de sincronización NVD (HU-005)."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

from atrox.threat_intel.cve_store import CveStore
from atrox.threat_intel.models import CVEEntry, CveSyncStatusEnum
from atrox.threat_intel.nvd_client import NvdClientError
from atrox.threat_intel.service import NvdSyncService, SyncInProgressError
from tests.fixtures.nvd_fakes import FakeNvdClient


def _make_cve(cve_id: str) -> CVEEntry:
    return CVEEntry(
        cve_id=cve_id,
        description="desc",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        published_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )


@pytest.fixture
def service(tmp_path: Path) -> NvdSyncService:
    store = CveStore(
        store_path=tmp_path / "cves.jsonl",
        sync_status_path=tmp_path / "last_sync.json",
    )
    return NvdSyncService(client=FakeNvdClient(), store=store)


class TestNvdSyncService:
    """Scenario: Job programado descarga e indexa CVEs nuevos/modificados."""

    def test_first_sync_indexes_full_catalog(self, tmp_path: Path) -> None:
        store = CveStore(
            store_path=tmp_path / "cves.jsonl",
            sync_status_path=tmp_path / "last_sync.json",
        )
        client = FakeNvdClient(entries=[_make_cve("CVE-2021-44228")])
        svc = NvdSyncService(client=client, store=store)

        status = asyncio.run(svc.sync_once())

        assert status.status == CveSyncStatusEnum.OK
        assert status.cves_added == 1
        assert status.cves_updated == 0
        assert status.cves_total == 1
        assert client.last_since is None, "Primera sincronización debe ser completa"
        assert asyncio.run(store.get("CVE-2021-44228")) is not None

    def test_subsequent_sync_uses_last_success_as_delta(self, tmp_path: Path) -> None:
        store = CveStore(
            store_path=tmp_path / "cves.jsonl",
            sync_status_path=tmp_path / "last_sync.json",
        )
        client = FakeNvdClient(entries=[_make_cve("CVE-2021-44228")])
        svc = NvdSyncService(client=client, store=store)

        asyncio.run(svc.sync_once())
        client.last_since = None
        asyncio.run(svc.sync_once())

        assert client.last_since is not None, "Delta debe usar la última sincronización exitosa"

    def test_sync_upserts_modified_cves(self, tmp_path: Path) -> None:
        store = CveStore(
            store_path=tmp_path / "cves.jsonl",
            sync_status_path=tmp_path / "last_sync.json",
        )
        svc = NvdSyncService(client=FakeNvdClient(entries=[_make_cve("CVE-2021-0001")]), store=store)
        asyncio.run(svc.sync_once())

        updated = _make_cve("CVE-2021-0001")
        updated.cvss_score = 6.0
        svc._client.entries = [updated]

        status = asyncio.run(svc.sync_once())

        assert status.cves_updated == 1
        assert asyncio.run(store.get("CVE-2021-0001")).cvss_score == 6.0

    def test_network_error_is_logged_without_raising(self, tmp_path: Path) -> None:
        """Criterio: registra errores de red sin interrumpir escaneos activos."""
        store = CveStore(
            store_path=tmp_path / "cves.jsonl",
            sync_status_path=tmp_path / "last_sync.json",
        )
        svc = NvdSyncService(
            client=FakeNvdClient(error=NvdClientError("Sin conexión con NVD")),
            store=store,
        )

        status = asyncio.run(svc.sync_once())

        assert status.status == CveSyncStatusEnum.ERROR
        assert "Sin conexión con NVD" in (status.last_error or "")
        assert status.cves_total == 0

    def test_network_error_keeps_previous_catalog_and_success(self, tmp_path: Path) -> None:
        store = CveStore(
            store_path=tmp_path / "cves.jsonl",
            sync_status_path=tmp_path / "last_sync.json",
        )
        good = FakeNvdClient(entries=[_make_cve("CVE-2021-44228")])
        svc = NvdSyncService(client=good, store=store)
        asyncio.run(svc.sync_once())

        failing = FakeNvdClient(error=NvdClientError("Timeout"))
        svc._client = failing
        status = asyncio.run(svc.sync_once())

        assert status.status == CveSyncStatusEnum.ERROR
        assert status.last_success_at is not None, "Conserva la última sincronización exitosa"
        assert asyncio.run(store.get("CVE-2021-44228")) is not None

    def test_force_full_ignores_previous_sync(self, tmp_path: Path) -> None:
        store = CveStore(
            store_path=tmp_path / "cves.jsonl",
            sync_status_path=tmp_path / "last_sync.json",
        )
        client = FakeNvdClient(entries=[_make_cve("CVE-2021-0001")])
        svc = NvdSyncService(client=client, store=store)
        asyncio.run(svc.sync_once())

        asyncio.run(svc.sync_once(force_full=True))

        assert client.last_since is None, "force_full ignora la última sincronización"

    def test_concurrent_sync_raises_in_progress(self, tmp_path: Path) -> None:
        store = CveStore(
            store_path=tmp_path / "cves.jsonl",
            sync_status_path=tmp_path / "last_sync.json",
        )
        svc = NvdSyncService(client=FakeNvdClient(entries=[_make_cve("CVE-2021-0001")]), store=store)

        async def scenario() -> None:
            first = asyncio.create_task(svc.sync_once())
            await asyncio.sleep(0)
            with pytest.raises(SyncInProgressError):
                await svc.sync_once()
            await first

        asyncio.run(scenario())

    def test_sync_once_safe_never_raises(self, tmp_path: Path) -> None:
        store = CveStore(
            store_path=tmp_path / "cves.jsonl",
            sync_status_path=tmp_path / "last_sync.json",
        )
        svc = NvdSyncService(
            client=FakeNvdClient(error=NvdClientError("boom")),
            store=store,
        )

        status = asyncio.run(svc.sync_once_safe())

        assert status is not None
        assert status.status == CveSyncStatusEnum.ERROR


class TestSyncStatusLog:
    """Scenario: Log de última sincronización consultable (DoD)."""

    def test_status_queryable_after_success(self, tmp_path: Path) -> None:
        store = CveStore(
            store_path=tmp_path / "cves.jsonl",
            sync_status_path=tmp_path / "last_sync.json",
        )
        svc = NvdSyncService(client=FakeNvdClient(entries=[_make_cve("CVE-2021-0001")]), store=store)
        asyncio.run(svc.sync_once())

        status = asyncio.run(svc.get_status())

        assert status.status == CveSyncStatusEnum.OK
        assert status.last_success_at is not None
        assert status.cves_total == 1
