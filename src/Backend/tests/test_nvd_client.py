"""Tests unitarios para el cliente asíncrono de la API NVD (HU-005)."""

import asyncio
from datetime import datetime, timezone

import pytest

from atrox.threat_intel.models import CVEEntry
from atrox.threat_intel.nvd_client import (
    NvdClient,
    NvdClientError,
    parse_nvd_vulnerability,
)
from tests.fixtures.nvd_fakes import FakeHttpClient, FakeResponse
from tests.fixtures.nvd_samples import nvd_page, nvd_vulnerability


# -- Parser de ítems NVD ------------------------------------------------------


class TestParseNvdVulnerability:
    """Scenario: Traducir un ítem NVD a CVEEntry (spec requirement)."""

    def test_parse_full_cve(self) -> None:
        raw = nvd_vulnerability(
            "CVE-2021-44228",
            description="Log4j remote code execution",
            base_score=10.0,
            base_severity="CRITICAL",
        )

        entry = parse_nvd_vulnerability(raw)

        assert isinstance(entry, CVEEntry)
        assert entry.cve_id == "CVE-2021-44228"
        assert entry.cvss_score == 10.0
        assert entry.cvss_severity == "CRITICAL"
        assert entry.cvss_vector.startswith("CVSS:3.1")
        assert entry.description == "Log4j remote code execution"
        assert entry.published_date.isoformat().startswith("2021-12-10")
        assert entry.last_modified_date is not None

    def test_parse_prefers_english_description(self) -> None:
        entry = parse_nvd_vulnerability(
            nvd_vulnerability("CVE-2020-0001", description="English description")
        )
        assert entry.description == "English description"

    def test_parse_without_cvss_metrics(self) -> None:
        entry = parse_nvd_vulnerability(
            nvd_vulnerability("CVE-2020-0002", base_score=None, base_severity=None)
        )
        assert entry.cvss_score is None
        assert entry.cvss_severity is None

    def test_parse_prefers_v31_over_v2_score(self) -> None:
        raw = {
            "cve": {
                "id": "CVE-2019-0003",
                "published": "2019-01-01T00:00:00.000",
                "lastModified": "2019-06-01T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Dual metrics"}],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "cvssData": {
                                "baseScore": 5.0,
                                "baseSeverity": "MEDIUM",
                            }
                        }
                    ],
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ],
                },
            }
        }

        entry = parse_nvd_vulnerability(raw)

        assert entry.cvss_score == 9.8
        assert entry.cvss_severity == "CRITICAL"

    def test_parse_missing_id_raises(self) -> None:
        with pytest.raises(NvdClientError):
            parse_nvd_vulnerability({"cve": {"id": ""}})


# -- Cliente HTTP -------------------------------------------------------------


class TestNvdClient:
    """Scenario: Descargar CVEs nuevos/modificados desde NVD (spec requirement)."""

    def test_fetch_changes_returns_parsed_entries(self) -> None:
        client = NvdClient(
            http_client=FakeHttpClient(
                [
                    nvd_page(
                        [
                            nvd_vulnerability("CVE-2021-44228"),
                            nvd_vulnerability("CVE-2022-0001", base_score=7.5, base_severity="HIGH"),
                        ]
                    )
                ]
            )
        )

        entries = asyncio.run(client.fetch_changes(since=None))

        assert len(entries) == 2
        assert {e.cve_id for e in entries} == {"CVE-2021-44228", "CVE-2022-0001"}

    def test_fetch_sends_lastmod_filter_when_since_given(self) -> None:
        fake = FakeHttpClient([nvd_page([nvd_vulnerability("CVE-2021-0001")])])
        client = NvdClient(http_client=fake)
        since = datetime(2024, 1, 1, tzinfo=timezone.utc)

        asyncio.run(client.fetch_changes(since=since))

        assert fake.requested_params[0]["lastModStartDate"].startswith("2024-01-01T")
        assert "lastModEndDate" in fake.requested_params[0]

    def test_fetch_sends_api_key_header(self) -> None:
        client = NvdClient(api_key="mi-llave", http_client=FakeHttpClient([nvd_page([])]))

        entries = asyncio.run(client.fetch_changes())

        assert entries == []

    def test_fetch_handles_pagination(self) -> None:
        first_page = nvd_page([nvd_vulnerability("CVE-2021-0001")], start_index=0)
        first_page["totalResults"] = 2001
        second_page = nvd_page([nvd_vulnerability("CVE-2021-0002")], start_index=2000)
        second_page["totalResults"] = 2001
        fake = FakeHttpClient([first_page, second_page])

        entries = asyncio.run(NvdClient(http_client=fake).fetch_changes())

        assert len(entries) == 2
        assert fake.requested_params[0]["startIndex"] == 0
        assert fake.requested_params[1]["startIndex"] == 2000

    def test_fetch_skips_malformed_items(self) -> None:
        """Un ítem malformado no debe abortar la sincronización completa."""
        page = nvd_page([nvd_vulnerability("CVE-2021-0001")])
        page["vulnerabilities"].append({"cve": {"id": "", "published": ""}})

        entries = asyncio.run(NvdClient(http_client=FakeHttpClient([page])).fetch_changes())

        assert len(entries) == 1
        assert entries[0].cve_id == "CVE-2021-0001"

    def test_network_error_raises_nvd_client_error(self) -> None:
        class FailingClient:
            async def get(self, url, params, headers):
                raise OSError("No hay conexión")

        with pytest.raises(NvdClientError):
            asyncio.run(NvdClient(http_client=FailingClient()).fetch_changes())

    def test_http_error_status_raises_nvd_client_error(self) -> None:
        class ErrorClient:
            async def get(self, url, params, headers):
                return FakeResponse(503, text="Service Unavailable")

        with pytest.raises(NvdClientError):
            asyncio.run(NvdClient(http_client=ErrorClient()).fetch_changes())
