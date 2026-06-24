# Tasks: Integrar Escaneo de Vulnerabilidades con Nuclei (HU-003)

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 420-460 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (foundation+wrapper+tests) -> PR 2 (API+wiring+integration) |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Models + fixtures + NucleiWrapper + config + unit tests | PR 1 | Base: HU/003; standalone, all tests pass without API |
| 2 | API router + wiring (main.py, __init__.py) + API tests + integration test | PR 2 | Base: PR 1 branch; depends on PR 1 |

## Phase 1: Foundation (models + config + fixtures)

- [x] 1.1 RED: Add test stubs in `tests/test_nuclei_wrapper.py` importing VulnSeverity, VulnFinding, VulnScanRequest, VulnScanResult -- tests fail (models missing). [Spec: Data Models]
- [x] 1.2 GREEN: Add VulnSeverity enum (info/low/medium/high/critical/unknown), VulnFinding, VulnScanRequest (reuse validate_target), VulnScanResult (reuse ScanStatus) to `atrox/scanner/models.py`. [Spec: Data Models]
- [x] 1.3 Add nuclei_path, nuclei_timeout_seconds, nuclei_sandbox_templates to `atrox/config.py` Settings class. [Spec: Configuration]
- [x] 1.4 Create `tests/fixtures/nuclei_samples.py` with JSONL strings: multi-finding, no-findings, malformed-line, unknown-severity. [Spec: JSONL Parsing, Testability]

## Phase 2: Core (wrapper + unit tests) -- TDD

- [x] 2.1 RED: Write `tests/test_nuclei_wrapper.py` unit tests with mock runners: successful scan with findings, scan with no findings, sandbox template resolution, severity filter args, malformed JSONL skip, unknown severity maps to UNKNOWN, FileNotFoundError, TimeoutError, empty stdout with non-zero exit. [Spec: Scan Execution, JSONL Parsing, Error Handling]
- [x] 2.2 GREEN: Create `atrox/scanner/nuclei_wrapper.py` with NucleiRunner type alias, NucleiWrapper class (scan, _execute, _parse_jsonl, sandbox path resolution via is_relative_to). [Spec: Scan Execution, JSONL Parsing, Error Handling]
- [x] 2.3 REFACTOR: Clean up wrapper -- extract constants, verify logging on skipped lines, confirm all tests green.

## Phase 3: Integration + Wiring

- [x] 3.1 RED: Write `tests/test_vulnscan_api.py` with dependency_overrides: POST /api/vulnscan/scan success, invalid target 422, response conforms to VulnScanResult. [Spec: API Endpoint]
- [x] 3.2 GREEN: Create `atrox/api/vulnscan.py` router (POST /api/vulnscan/scan) with get_nuclei_wrapper dependency following discovery.py pattern. [Spec: API Endpoint]
- [x] 3.3 Wire: Add `include_router(vulnscan_router)` in `atrox/main.py`, export NucleiWrapper in `atrox/scanner/__init__.py`. [Spec: API Endpoint]
- [x] 3.4 Create `tests/test_nuclei_integration.py` with `@pytest.mark.integration`: real NucleiWrapper.scan against localhost (skip if nuclei absent). [Spec: Testability]
