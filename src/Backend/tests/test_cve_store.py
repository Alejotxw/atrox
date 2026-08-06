"""Tests unitarios para el almacén del catálogo de CVEs (HU-005)."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from atrox.threat_intel.cve_store import CveStore
from atrox.threat_intel.models import CVEEntry, CveSyncStatus, CveSyncStatusEnum


def _make_cve(cve_id: str, severity: str = "CRITICAL", score: float = 9.8, desc: str = "desc") -> CVEEntry:
    return CVEEntry(
        cve_id=cve_id,
        description=desc,
        cvss_score=score,
        cvss_severity=severity,
        published_date=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_modified_date=datetime(2024, 6, 1, tzinfo=timezone.utc),
    )


@pytest.fixture
def store(tmp_path: Path) -> CveStore:
    return CveStore(
        store_path=tmp_path / "cves.jsonl",
        sync_status_path=tmp_path / "last_sync.json",
    )


class TestCveStore:
    """Scenario: Persistir CVE-ID, CVSS, descripción y fecha (spec requirement)."""

    def test_upsert_persists_and_reads_back(self, store: CveStore) -> None:
        cve = _make_cve("CVE-2021-44228")

        asyncio_run(store.upsert(cve))
        loaded = asyncio_run(store.get("CVE-2021-44228"))

        assert loaded is not None
        assert loaded.cve_id == "CVE-2021-44228"
        assert loaded.cvss_score == 9.8
        assert loaded.cvss_severity == "CRITICAL"
        assert loaded.description == "desc"
        assert loaded.published_date == cve.published_date

    def test_upsert_returns_added_and_updated_counts(self, store: CveStore) -> None:
        cve = _make_cve("CVE-2021-0001", score=7.0)

        added, updated = asyncio_run(store.upsert(cve))
        assert (added, updated) == (1, 0)

        modified = _make_cve("CVE-2021-0001", score=8.0)
        added, updated = asyncio_run(store.upsert(modified))
        assert (added, updated) == (0, 1)

    def test_persistence_survives_new_store_instance(self, tmp_path: Path) -> None:
        path = tmp_path / "cves.jsonl"
        status_path = tmp_path / "last_sync.json"
        asyncio_run(
            CveStore(store_path=path, sync_status_path=status_path).upsert(
                _make_cve("CVE-2021-44228")
            )
        )

        reloaded = CveStore(store_path=path, sync_status_path=status_path)
        entries = asyncio_run(reloaded.list_cves())

        assert len(entries) == 1
        assert entries[0].cve_id == "CVE-2021-44228"

    def test_list_filters_by_id_severity_and_query(self, store: CveStore) -> None:
        asyncio_run(
            store.bulk_upsert(
                [
                    _make_cve("CVE-2021-0001", "CRITICAL", desc="Apache log4j RCE"),
                    _make_cve("CVE-2022-0002", "HIGH", desc="OpenSSL buffer overflow"),
                    _make_cve("CVE-2023-0003", "MEDIUM", desc="Kernel privilege escalation"),
                ]
            )
        )

        by_id = asyncio_run(store.list_cves(cve_id="CVE-2022"))
        assert len(by_id) == 1 and by_id[0].cve_id == "CVE-2022-0002"

        by_sev = asyncio_run(store.list_cves(severity="high"))
        assert len(by_sev) == 1 and by_sev[0].cve_id == "CVE-2022-0002"

        by_query = asyncio_run(store.list_cves(query="apache"))
        assert len(by_query) == 1 and by_query[0].cve_id == "CVE-2021-0001"

    def test_list_pagination(self, store: CveStore) -> None:
        asyncio_run(
            store.bulk_upsert([_make_cve(f"CVE-2021-{i:04d}") for i in range(1, 6)])
        )

        page1 = asyncio_run(store.list_cves(limit=2, offset=0))
        page2 = asyncio_run(store.list_cves(limit=2, offset=2))

        assert [c.cve_id for c in page1] == ["CVE-2021-0001", "CVE-2021-0002"]
        assert [c.cve_id for c in page2] == ["CVE-2021-0003", "CVE-2021-0004"]

    def test_get_unknown_returns_none(self, store: CveStore) -> None:
        assert asyncio_run(store.get("CVE-9999-0001")) is None


class TestSyncStatusStore:
    """Scenario: Log de última sincronización consultable (DoD)."""

    def test_default_status_before_first_sync(self, store: CveStore) -> None:
        status = asyncio_run(store.get_sync_status())

        assert status.status == CveSyncStatusEnum.ERROR
        assert "no se ha ejecutado" in (status.last_error or "")

    def test_save_and_load_sync_status(self, store: CveStore) -> None:
        expected = CveSyncStatus(
            status=CveSyncStatusEnum.OK,
            last_attempt_at=datetime(2024, 6, 1, tzinfo=timezone.utc),
            last_success_at=datetime(2024, 6, 1, tzinfo=timezone.utc),
            cves_total=10,
            cves_added=8,
            cves_updated=2,
        )

        asyncio_run(store.save_sync_status(expected))
        loaded = asyncio_run(store.get_sync_status())

        assert loaded.status == CveSyncStatusEnum.OK
        assert loaded.cves_total == 10
        assert loaded.cves_added == 8
        assert loaded.cves_updated == 2
        assert loaded.last_success_at == expected.last_success_at


def asyncio_run(coro):
    import asyncio

    return asyncio.run(coro)
