"""Tests del enriquecimiento de hallazgos cuando Nuclei no trae CVEs."""

from uuid import uuid4

from atrox.queue.models import Job, JobStatus, JobType
from atrox.queue.service import JobQueue
from atrox.scanner.audit_outcome import (
    empty_audit_findings,
    findings_from_discovery_hosts,
    resolve_vulnscan_findings,
)
from atrox.scanner.models import HostFinding, PortFinding, VulnSeverity


def test_empty_audit_always_returns_rows():
    findings = empty_audit_findings("corp.internal.uide.edu.ec", hosts=[])
    assert len(findings) >= 2
    ids = {f.template_id for f in findings}
    assert "audit:no-open-ports" in ids
    assert "audit:nuclei-empty" in ids
    assert all(f.severity == VulnSeverity.INFO for f in findings)


def test_surface_from_open_ports():
    hosts = [
        HostFinding(
            address="10.0.0.1",
            status="up",
            ports=[PortFinding(port=443, protocol="tcp", service="https", version="nginx")],
        )
    ]
    surface = findings_from_discovery_hosts("example.com", hosts)
    assert len(surface) == 1
    assert surface[0].template_id.startswith("recon:port-443")
    assert "nginx" in surface[0].name

    findings = empty_audit_findings("example.com", hosts=hosts)
    assert any(f.template_id.startswith("recon:") for f in findings)
    assert any(f.template_id == "audit:nuclei-empty" for f in findings)
    assert not any(f.template_id == "audit:no-open-ports" for f in findings)


def test_resolve_uses_nuclei_when_present():
    queue = JobQueue(max_concurrent=2, max_queue_size=10)
    job = Job(
        id=uuid4(),
        job_type=JobType.VULNSCAN,
        status=JobStatus.DONE,
        params={"target": "example.com"},
        result={
            "findings": [
                {
                    "template_id": "cve-2021-44228",
                    "name": "Log4Shell",
                    "severity": "critical",
                    "host": "example.com",
                    "matched_at": "https://example.com",
                }
            ]
        },
    )
    resolved = resolve_vulnscan_findings(job, queue)
    assert len(resolved) == 1
    assert resolved[0].template_id == "cve-2021-44228"


def test_resolve_synthesizes_when_nuclei_empty():
    queue = JobQueue(max_concurrent=2, max_queue_size=10)
    disc = Job(
        id=uuid4(),
        job_type=JobType.DISCOVERY,
        status=JobStatus.DONE,
        params={"target": "corp.internal.uide.edu.ec"},
        result={"hosts": []},
    )
    queue._jobs[disc.id] = disc  # noqa: SLF001 — test fixture

    vuln = Job(
        id=uuid4(),
        job_type=JobType.VULNSCAN,
        status=JobStatus.DONE,
        params={"target": "corp.internal.uide.edu.ec"},
        result={"findings": []},
    )
    resolved = resolve_vulnscan_findings(vuln, queue)
    assert len(resolved) >= 2
    assert any(f.template_id == "audit:nuclei-empty" for f in resolved)
