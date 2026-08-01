"""Tests para la ejecución manual del job de sincronización NVD (HU-005 DoD)."""

from datetime import datetime, timezone

import atrox.threat_intel.__main__ as cli
from atrox.threat_intel.cve_store import CveStore
from atrox.threat_intel.models import CVEEntry
from atrox.threat_intel.nvd_client import NvdClientError
from atrox.threat_intel.service import NvdSyncService
from tests.fixtures.nvd_fakes import FakeNvdClient


def _make_cve() -> CVEEntry:
    return CVEEntry(
        cve_id="CVE-2021-44228",
        description="Log4j RCE",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        published_date=datetime(2021, 12, 10, tzinfo=timezone.utc),
    )


def _make_service(tmp_path, client: FakeNvdClient) -> NvdSyncService:
    store = CveStore(
        store_path=tmp_path / "cves.jsonl",
        sync_status_path=tmp_path / "last_sync.json",
    )
    return NvdSyncService(client=client, store=store)


class TestThreatIntelCli:
    """Scenario: Script/job ejecutable manualmente (DoD HU-005)."""

    def test_main_returns_zero_on_success(self, tmp_path, monkeypatch, capsys) -> None:
        monkeypatch.setattr(cli, "build_nvd_sync_service", lambda: _make_service(tmp_path, FakeNvdClient(entries=[_make_cve()])))
        monkeypatch.setattr("sys.argv", ["atrox-nvd-sync"])

        exit_code = cli.main()

        assert exit_code == 0
        output = capsys.readouterr().out
        assert '"status": "ok"' in output
        assert '"cves_total": 1' in output

    def test_main_returns_one_on_failure(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(
            cli,
            "build_nvd_sync_service",
            lambda: _make_service(tmp_path, FakeNvdClient(error=NvdClientError("Sin conexión"))),
        )
        monkeypatch.setattr("sys.argv", ["atrox-nvd-sync"])

        exit_code = cli.main()

        assert exit_code == 1

    def test_force_full_flag_is_accepted(self, tmp_path, monkeypatch) -> None:
        client = FakeNvdClient(entries=[_make_cve()])
        monkeypatch.setattr(cli, "build_nvd_sync_service", lambda: _make_service(tmp_path, client))
        monkeypatch.setattr("sys.argv", ["atrox-nvd-sync", "--force-full"])

        exit_code = cli.main()

        assert exit_code == 0
        assert client.last_since is None, "--force-full debe descargar el catálogo completo"
