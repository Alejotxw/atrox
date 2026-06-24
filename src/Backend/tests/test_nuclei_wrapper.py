"""Unit tests for NucleiWrapper — Strict TDD."""

import asyncio
import os
import tempfile

import pytest

from atrox.scanner.models import (
    ScanStatus,
    VulnFinding,
    VulnScanRequest,
    VulnScanResult,
    VulnSeverity,
)
from atrox.scanner.nuclei_wrapper import NucleiWrapper
from tests.fixtures.nuclei_samples import (
    SAMPLE_NUCLEI_JSONL_MALFORMED,
    SAMPLE_NUCLEI_JSONL_MISSING_REQUIRED,
    SAMPLE_NUCLEI_JSONL_MULTI,
    SAMPLE_NUCLEI_JSONL_OPTIONAL_DEFAULTS,
    SAMPLE_NUCLEI_JSONL_UNKNOWN_SEVERITY,
)


# ── Task 1.1: Model import tests (RED) ──────────────────────────────


class TestVulnSeverityEnum:
    def test_severity_has_all_expected_values(self) -> None:
        expected = {"info", "low", "medium", "high", "critical", "unknown"}
        actual = {s.value for s in VulnSeverity}
        assert actual == expected

    def test_severity_is_string_enum(self) -> None:
        assert isinstance(VulnSeverity.CRITICAL, str)
        assert VulnSeverity.CRITICAL == "critical"


class TestVulnFindingModel:
    def test_finding_accepts_required_fields(self) -> None:
        finding = VulnFinding(
            template_id="cve-2021-41773",
            name="Apache Path Traversal",
            severity=VulnSeverity.CRITICAL,
            host="http://192.168.1.10",
            matched_at="http://192.168.1.10/traversal",
        )
        assert finding.template_id == "cve-2021-41773"
        assert finding.severity == VulnSeverity.CRITICAL

    def test_finding_defaults_optional_fields(self) -> None:
        finding = VulnFinding(
            template_id="test",
            name="Test",
            severity=VulnSeverity.LOW,
            host="http://10.0.0.1",
            matched_at="http://10.0.0.1/test",
        )
        assert finding.tags == []
        assert finding.description == ""
        assert finding.references == []
        assert finding.extracted_results == []
        assert finding.scan_type == ""
        assert finding.ip == ""
        assert finding.timestamp == ""


class TestVulnScanRequestModel:
    def test_request_validates_ip_target(self) -> None:
        req = VulnScanRequest(target="192.168.1.1")
        assert req.target == "192.168.1.1"

    def test_request_validates_fqdn_target(self) -> None:
        req = VulnScanRequest(target="scanme.nmap.org")
        assert req.target == "scanme.nmap.org"

    def test_request_rejects_invalid_target(self) -> None:
        with pytest.raises(ValueError, match="Objetivo inválido"):
            VulnScanRequest(target="not a valid target!!!")

    def test_request_defaults_optional_fields(self) -> None:
        req = VulnScanRequest(target="192.168.1.1")
        assert req.templates == []
        assert req.severities == []
        assert req.tags == []


class TestVulnScanResultModel:
    def test_result_uses_scan_status_enum(self) -> None:
        result = VulnScanResult(
            target="192.168.1.1",
            status=ScanStatus.COMPLETED,
        )
        assert result.status == ScanStatus.COMPLETED
        assert result.findings == []
        assert result.error is None


# ── Task 2.1: NucleiWrapper unit tests (RED → GREEN → REFACTOR) ─────


class TestNucleiWrapperSuccessfulScan:
    """Scenario: Successful scan with multiple findings."""

    def test_scan_returns_completed_with_findings(self) -> None:
        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, SAMPLE_NUCLEI_JSONL_MULTI, ""

        wrapper = NucleiWrapper(runner=mock_runner)
        result = asyncio.run(wrapper.scan("192.168.1.10"))

        assert result.status == ScanStatus.COMPLETED
        assert result.target == "192.168.1.10"
        assert len(result.findings) == 2

    def test_scan_parses_finding_fields_correctly(self) -> None:
        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, SAMPLE_NUCLEI_JSONL_MULTI, ""

        wrapper = NucleiWrapper(runner=mock_runner)
        result = asyncio.run(wrapper.scan("192.168.1.10"))

        first = result.findings[0]
        assert first.template_id == "cve-2021-41773"
        assert first.name == "Apache HTTP Server Path Traversal"
        assert first.severity == VulnSeverity.CRITICAL
        assert first.host == "http://192.168.1.10:80"
        assert first.matched_at == "http://192.168.1.10:80/cgi-bin/.%2e/.%2e/etc/passwd"
        assert first.tags == ["cve", "apache", "rce"]
        assert first.description == "A flaw was found in Apache HTTP Server."
        assert first.references == ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]
        assert first.extracted_results == ["root:x:0:0:root:/root:/bin/bash"]
        assert first.ip == "192.168.1.10"
        assert first.scan_type == "http"
        assert first.timestamp == "2024-01-15T14:30:00Z"

    def test_scan_parses_second_finding(self) -> None:
        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, SAMPLE_NUCLEI_JSONL_MULTI, ""

        wrapper = NucleiWrapper(runner=mock_runner)
        result = asyncio.run(wrapper.scan("192.168.1.10"))

        second = result.findings[1]
        assert second.template_id == "cve-2023-22515"
        assert second.severity == VulnSeverity.HIGH


class TestNucleiWrapperNoFindings:
    """Scenario: Scan with no findings."""

    def test_scan_returns_completed_with_empty_findings(self) -> None:
        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, "", ""

        wrapper = NucleiWrapper(runner=mock_runner)
        result = asyncio.run(wrapper.scan("192.168.1.10"))

        assert result.status == ScanStatus.COMPLETED
        assert result.findings == []
        assert result.error is None


class TestNucleiWrapperSandboxTemplates:
    """Scenario: Sandbox template resolution."""

    def test_scan_includes_sandbox_template_arg(self) -> None:
        captured_args: list[list[str]] = []

        async def capturing_runner(args: list[str]) -> tuple[int, str, str]:
            captured_args.append(args)
            return 0, "", ""

        with tempfile.TemporaryDirectory() as sandbox:
            template_file = os.path.join(sandbox, "cve-test.yaml")
            with open(template_file, "w") as f:
                f.write("# template")

            wrapper = NucleiWrapper(
                sandbox_templates=sandbox,
                runner=capturing_runner,
            )
            asyncio.run(wrapper.scan("192.168.1.10", templates=["cve-test.yaml"]))

        assert len(captured_args) == 1
        args = captured_args[0]
        assert "-t" in args
        t_index = args.index("-t")
        resolved_path = args[t_index + 1]
        assert resolved_path.endswith("cve-test.yaml")
        assert os.path.isabs(resolved_path)

    def test_scan_rejects_path_traversal_template(self) -> None:
        with tempfile.TemporaryDirectory() as sandbox:
            wrapper = NucleiWrapper(
                sandbox_templates=sandbox,
                runner=lambda _: None,  # type: ignore[arg-type,return-value]
            )
            result = asyncio.run(
                wrapper.scan("192.168.1.10", templates=["../../etc/passwd"])
            )

        assert result.status == ScanStatus.ERROR
        assert "no permitida" in (result.error or "").lower() or "sandbox" in (result.error or "").lower()


class TestNucleiWrapperSeverityFilter:
    """Scenario: Severity filter applied."""

    def test_scan_adds_severity_flag(self) -> None:
        captured_args: list[list[str]] = []

        async def capturing_runner(args: list[str]) -> tuple[int, str, str]:
            captured_args.append(args)
            return 0, "", ""

        wrapper = NucleiWrapper(runner=capturing_runner)
        asyncio.run(wrapper.scan("192.168.1.10", severities=["critical", "high"]))

        args = captured_args[0]
        assert "-severity" in args
        sev_index = args.index("-severity")
        assert args[sev_index + 1] == "critical,high"

    def test_scan_adds_tags_flag(self) -> None:
        captured_args: list[list[str]] = []

        async def capturing_runner(args: list[str]) -> tuple[int, str, str]:
            captured_args.append(args)
            return 0, "", ""

        wrapper = NucleiWrapper(runner=capturing_runner)
        asyncio.run(wrapper.scan("192.168.1.10", tags=["cve", "apache"]))

        args = captured_args[0]
        assert "-tags" in args
        tags_index = args.index("-tags")
        assert args[tags_index + 1] == "cve,apache"


class TestNucleiWrapperMalformedJSONL:
    """Scenario: Malformed JSONL line in output."""

    def test_scan_skips_malformed_lines_keeps_valid(self) -> None:
        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, SAMPLE_NUCLEI_JSONL_MALFORMED, ""

        wrapper = NucleiWrapper(runner=mock_runner)
        result = asyncio.run(wrapper.scan("192.168.1.10"))

        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 2
        assert result.findings[0].template_id == "cve-2021-41773"
        assert result.findings[1].template_id == "tech-detect"


class TestNucleiWrapperMissingRequiredFields:
    """Scenario: Lines missing required fields are skipped."""

    def test_scan_skips_lines_missing_template_id_or_name(self) -> None:
        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, SAMPLE_NUCLEI_JSONL_MISSING_REQUIRED, ""

        wrapper = NucleiWrapper(runner=mock_runner)
        result = asyncio.run(wrapper.scan("10.0.0.1"))

        assert result.status == ScanStatus.COMPLETED
        assert len(result.findings) == 1
        assert result.findings[0].template_id == "ok"
        assert result.findings[0].name == "Valid Finding"


class TestNucleiWrapperUnknownSeverity:
    """Scenario: Unknown severity value."""

    def test_scan_maps_unknown_severity_to_enum(self) -> None:
        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, SAMPLE_NUCLEI_JSONL_UNKNOWN_SEVERITY, ""

        wrapper = NucleiWrapper(runner=mock_runner)
        result = asyncio.run(wrapper.scan("10.0.0.1"))

        assert len(result.findings) == 1
        assert result.findings[0].severity == VulnSeverity.UNKNOWN


class TestNucleiWrapperOptionalDefaults:
    """Scenario: Optional fields default correctly."""

    def test_scan_defaults_optional_fields_when_absent(self) -> None:
        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, SAMPLE_NUCLEI_JSONL_OPTIONAL_DEFAULTS, ""

        wrapper = NucleiWrapper(runner=mock_runner)
        result = asyncio.run(wrapper.scan("10.0.0.1"))

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.tags == []
        assert finding.description == ""
        assert finding.references == []
        assert finding.extracted_results == []
        assert finding.scan_type == ""
        assert finding.ip == ""
        assert finding.timestamp == ""


class TestNucleiWrapperErrorHandling:
    """Scenario: Error conditions."""

    def test_scan_handles_file_not_found_error(self) -> None:
        async def missing_runner(_args: list[str]) -> tuple[int, str, str]:
            raise FileNotFoundError("nuclei not found")

        wrapper = NucleiWrapper(runner=missing_runner)
        result = asyncio.run(wrapper.scan("127.0.0.1"))

        assert result.status == ScanStatus.ERROR
        assert "Nuclei no encontrado" in (result.error or "")

    def test_scan_handles_timeout_error(self) -> None:
        async def slow_runner(_args: list[str]) -> tuple[int, str, str]:
            await asyncio.sleep(2)
            return 0, "", ""

        wrapper = NucleiWrapper(timeout_seconds=1, runner=slow_runner)
        result = asyncio.run(wrapper.scan("192.168.1.10"))

        assert result.status == ScanStatus.TIMEOUT
        assert "tiempo límite" in (result.error or "").lower() or "1s" in (result.error or "")

    def test_scan_handles_empty_stdout_nonzero_exit(self) -> None:
        async def error_runner(_args: list[str]) -> tuple[int, str, str]:
            return 1, "", "nuclei: fatal error"

        wrapper = NucleiWrapper(runner=error_runner)
        result = asyncio.run(wrapper.scan("192.168.1.10"))

        assert result.status == ScanStatus.ERROR
        assert "nuclei: fatal error" in (result.error or "")

    def test_scan_handles_generic_exception(self) -> None:
        async def boom_runner(_args: list[str]) -> tuple[int, str, str]:
            raise RuntimeError("unexpected crash")

        wrapper = NucleiWrapper(runner=boom_runner)
        result = asyncio.run(wrapper.scan("192.168.1.10"))

        assert result.status == ScanStatus.ERROR
        assert "unexpected crash" in (result.error or "")


class TestNucleiWrapperCLIArgs:
    """Verify correct CLI arg construction."""

    def test_scan_builds_base_args_correctly(self) -> None:
        captured_args: list[list[str]] = []

        async def capturing_runner(args: list[str]) -> tuple[int, str, str]:
            captured_args.append(args)
            return 0, "", ""

        wrapper = NucleiWrapper(runner=capturing_runner)
        asyncio.run(wrapper.scan("192.168.1.10"))

        args = captured_args[0]
        assert "-u" in args
        u_index = args.index("-u")
        assert args[u_index + 1] == "192.168.1.10"
        assert "-jsonl" in args
        assert "-silent" in args
        assert "-nc" in args
        assert "-or" in args
