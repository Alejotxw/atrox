"""Hallazgos de resultado de auditoría cuando Nuclei no trae CVEs.

Mantiene Impacto / Trazabilidad / Reportes alineados: si el job vulnscan
terminó sin findings, se sintetizan filas informativas a partir del
descubrimiento Nmap (mismo target) o del resultado negativo del escaneo.
"""

from __future__ import annotations

from datetime import datetime, timezone

from atrox.queue.models import Job, JobStatus, JobType
from atrox.queue.service import JobQueue
from atrox.scanner.models import HostFinding, VulnFinding, VulnSeverity


def _normalize_target(value: str) -> str:
    return (value or "").strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")


def latest_discovery_hosts(queue: JobQueue, target: str) -> list[HostFinding]:
    """Último discovery DONE del mismo objetivo (si existe)."""
    needle = _normalize_target(target)
    candidates: list[Job] = []
    for job in queue.list_jobs():
        if job.job_type != JobType.DISCOVERY or job.status != JobStatus.DONE:
            continue
        if not job.result or not isinstance(job.result, dict):
            continue
        if _normalize_target(str(job.params.get("target", ""))) != needle:
            continue
        candidates.append(job)

    if not candidates:
        return []

    candidates.sort(
        key=lambda j: j.finished_at or j.created_at,
        reverse=True,
    )
    raw_hosts = candidates[0].result.get("hosts", []) if candidates[0].result else []
    return [HostFinding(**host) if isinstance(host, dict) else host for host in raw_hosts]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def findings_from_discovery_hosts(target: str, hosts: list[HostFinding]) -> list[VulnFinding]:
    """Puertos/servicios reales de Nmap como hallazgos informativos (no CVEs)."""
    ts = _now_iso()
    out: list[VulnFinding] = []
    for host in hosts:
        address = host.address or target
        for port in host.ports:
            service = port.service or "unknown"
            version = (port.version or "").strip()
            version_bit = f" ({version})" if version else ""
            matched = f"{address}:{port.port}"
            out.append(
                VulnFinding(
                    template_id=f"recon:port-{port.port}-{port.protocol}",
                    name=f"Servicio expuesto: {service}{version_bit} en {port.port}/{port.protocol}",
                    severity=VulnSeverity.INFO,
                    host=address,
                    matched_at=matched,
                    tags=["recon", "nmap", "surface"],
                    description=(
                        f"Reconocimiento Nmap detectó el puerto {port.port}/{port.protocol} "
                        f"abierto en {address} con servicio '{service}'{version_bit}. "
                        "No es una vulnerabilidad CVE; es superficie de ataque observada."
                    ),
                    references=[],
                    extracted_results=[],
                    scan_type="discovery",
                    ip=address,
                    timestamp=ts,
                )
            )
    return out


def empty_audit_findings(
    target: str,
    *,
    hosts: list[HostFinding],
    nuclei_error: str | None = None,
) -> list[VulnFinding]:
    """Siempre al menos un hallazgo informativo del resultado de la auditoría."""
    ts = _now_iso()
    open_ports = sum(len(h.ports) for h in hosts)
    active_hosts = len([h for h in hosts if (h.status or "").lower() in {"up", "open", ""} and h.ports])
    if active_hosts == 0:
        active_hosts = len([h for h in hosts if h.ports])

    findings = findings_from_discovery_hosts(target, hosts)

    if open_ports == 0:
        findings.append(
            VulnFinding(
                template_id="audit:no-open-ports",
                name="Sin hosts/puertos abiertos en el rango de reconocimiento",
                severity=VulnSeverity.INFO,
                host=target,
                matched_at=target,
                tags=["audit", "recon", "nmap", "negative"],
                description=(
                    f"Nmap no reportó puertos abiertos para '{target}' en el rango auditado. "
                    "Puede deberse a filtrado de red, host caído, DNS interno o puertos fuera del rango."
                ),
                scan_type="discovery",
                ip="",
                timestamp=ts,
            )
        )

    nuclei_name = (
        f"Nuclei incompleto: {nuclei_error}"
        if nuclei_error
        else "Escaneo Nuclei sin vulnerabilidades critical/high/medium"
    )
    nuclei_desc = (
        f"El job de vulnerabilidades sobre '{target}' no dejó CVEs persistidos"
        + (f" ({nuclei_error})." if nuclei_error else ".")
        + " El informe refleja este resultado negativo junto con la superficie Nmap si existió."
    )
    findings.append(
        VulnFinding(
            template_id="audit:nuclei-empty" if not nuclei_error else "audit:nuclei-error",
            name=nuclei_name,
            severity=VulnSeverity.INFO,
            host=target,
            matched_at=target,
            tags=["audit", "nuclei", "negative"],
            description=nuclei_desc,
            scan_type="vulnscan",
            ip="",
            timestamp=ts,
        )
    )
    return findings


def resolve_vulnscan_findings(job: Job, queue: JobQueue) -> list[VulnFinding]:
    """Fuente única para UI/reportes: CVEs reales o resultado informativo del escaneo."""
    raw: list = []
    if job.result and isinstance(job.result, dict):
        raw = job.result.get("findings", []) or []

    findings = [VulnFinding(**f) if isinstance(f, dict) else f for f in raw]
    if findings:
        return findings

    if job.job_type != JobType.VULNSCAN:
        return []

    target = str(job.params.get("target", "objetivo"))
    hosts = latest_discovery_hosts(queue, target)
    nuclei_error = job.error
    if isinstance(job.result, dict):
        err = job.result.get("error")
        if isinstance(err, str) and err.strip():
            nuclei_error = err.strip()
    return empty_audit_findings(target, hosts=hosts, nuclei_error=nuclei_error)
