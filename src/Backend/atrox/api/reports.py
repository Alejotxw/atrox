"""Router REST de generación y exportación de reportes ejecutivos (HU-023) y técnicos (HU-024).

Rutas protegidas por MFA:
- `GET /api/reports/executive/{scan_id}`: Genera y descarga el PDF ejecutivo (HU-023).
- `POST /api/reports/executive`: Genera un PDF ejecutivo a partir de datos explícitos.
- `GET /api/reports/technical/{scan_id}?format=pdf|html`: Genera y descarga el reporte técnico detallado (HU-024).
- `POST /api/reports/technical?format=pdf|html`: Genera un reporte técnico a partir de datos explícitos.

Rutas de persistencia cifrada (HU-007):
- `POST /api/reports`: Persiste un reporte cifrando contenido sensible en reposo.
- `GET /api/reports`: Lista los reportes persistidos.
- `GET /api/reports/{report_id}`: Obtiene un reporte persistido por ID.
"""

import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from atrox.api.jobs import get_job_queue
from atrox.persistence.deps import get_persistence
from atrox.persistence.models import ReportCreate, ReportRecord
from atrox.persistence.service import EncryptedPersistenceService
from atrox.queue.service import JobQueue
from atrox.reports.generator import ExecutiveReportGenerator
from atrox.reports.models import ExecutiveReportData, SeverityHeatmap, TechnicalFindingItem, TechnicalReportData, TopRiskItem
from atrox.reports.technical_generator import TechnicalReportGenerator
from atrox.scanner.audit_outcome import resolve_vulnscan_findings
from atrox.scanner.models import VulnFinding
from atrox.security.auth_deps import require_mfa_admin

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _calculate_overall_risk(critical_cnt: int, high_cnt: int, medium_cnt: int) -> str:
    if critical_cnt > 0:
        return "CRÍTICO"
    if high_cnt > 0:
        return "ALTO"
    if medium_cnt > 0:
        return "MEDIO"
    return "BAJO"


def _generate_business_impact_narrative(target: str, critical_cnt: int, high_cnt: int, total_cnt: int) -> tuple[str, str]:
    if total_cnt == 0:
        summary = (
            f"El escaneo de seguridad ejecutado sobre el activo objetivo '{target}' no identificó "
            "vulnerabilidades ni vectores de amenaza activos durante la evaluación."
        )
        impact = (
            "El estado de postura de seguridad actual refleja un nivel de riesgo bajo. "
            "Se recomienda mantener las políticas de monitoreo continuo y parcheo regular."
        )
        return summary, impact

    summary = (
        f"Durante la evaluación de seguridad en '{target}', se identificaron un total de {total_cnt} hallazgos, "
        f"de los cuales {critical_cnt} corresponden a vulnerabilidades de severidad CRÍTICA y {high_cnt} a severidad ALTA. "
        "Estos hallazgos representan puntos expuestos que podrían ser explotados por atacantes externos."
    )

    if critical_cnt > 0:
        impact = (
            "IMPACTO DE NEGOCIO CRÍTICO: Existe riesgo inminente de compromiso total de la infraestructura, "
            "fuga de datos confidenciales y la interrupción no autorizada de servicios operativos clave. "
            "Se requiere la intervención e implementación de parches de mitigación con prioridad inmediata."
        )
    elif high_cnt > 0:
        impact = (
            "IMPACTO DE NEGOCIO ALTO: Las vulnerabilidades detectadas permiten el acceso no autorizado a componentes "
            "sensibles del sistema y la elevación de privilegios. Podrían generar pérdidas de confidencialidad e integridad."
        )
    else:
        impact = (
            "IMPACTO DE NEGOCIO MODERADO: Los hallazgos representan inconsistencias de configuración e información expuesta "
            "que requieren remediación dentro del ciclo operativo estándar de mantenimiento."
        )

    return summary, impact


def _extract_cves(finding: VulnFinding) -> list[str]:
    cves = set()
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    
    for tag in finding.tags:
        found = cve_pattern.findall(tag)
        for c in found:
            cves.add(c.upper())
            
    for ref in finding.references:
        found = cve_pattern.findall(ref)
        for c in found:
            cves.add(c.upper())
            
    if finding.template_id:
        found = cve_pattern.findall(finding.template_id)
        for c in found:
            cves.add(c.upper())

    return sorted(list(cves))


def _generate_technical_finding_details(finding: VulnFinding, index: int) -> TechnicalFindingItem:
    cve_list = _extract_cves(finding)
    
    # Evidencia / PoC
    poc_lines = [
        f"Petición/Ubicación Objetivo: {finding.matched_at or finding.host}",
        f"Plantilla Nuclei Identificadora: {finding.template_id}",
    ]
    if finding.extracted_results:
        poc_lines.append("Resultados Extraídos en Escaneo:")
        poc_lines.extend([f"  - {res}" for res in finding.extracted_results])
    else:
        poc_lines.append(f"Respuesta de Verificación: Patrón detectado en {finding.matched_at or finding.host}")
    
    poc_evidence = "\n".join(poc_lines)

    # Remediation steps & commands
    remediation_steps = (
        "1. Verificar la versión actual del servicio afectado en el servidor objetivo.\n"
        "2. Aplicar los parches de seguridad del fabricante para resolver las vulnerabilidades reportadas.\n"
        "3. Restringir el acceso de red a puertos administrativos mediante reglas de Firewall/Security Groups.\n"
        "4. Re-ejecutar el escaneo de validación automatizado para confirmar la remediación."
    )

    pkg_name = finding.template_id.split("-")[0] if "-" in finding.template_id else "package"
    remediation_commands = [
        f"sudo apt-get update && sudo apt-get install --only-upgrade {pkg_name}",
        f"sudo systemctl restart {pkg_name} || sudo systemctl reload nginx",
        f"nuclei -t {finding.template_id} -u {finding.matched_at or finding.host}",
    ]

    return TechnicalFindingItem(
        item_id=index,
        template_id=finding.template_id,
        name=finding.name,
        severity=finding.severity.upper(),
        host=finding.host,
        matched_at=finding.matched_at,
        cve_ids=cve_list,
        tags=finding.tags,
        description=finding.description or "Vulnerabilidad detectada durante el análisis de seguridad.",
        poc_evidence=poc_evidence,
        remediation_steps=remediation_steps,
        remediation_commands=remediation_commands,
        references=finding.references,
    )


@router.get("/executive/{scan_id}", response_class=Response)
async def export_executive_report_pdf(
    scan_id: UUID,
    request: Request,
    queue: JobQueue = Depends(get_job_queue),
    user_info: dict = Depends(require_mfa_admin),
) -> Response:
    """Genera y descarga el reporte ejecutivo en PDF para un escaneo específico (HU-023)."""
    job = queue.get_job(scan_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Escaneo con ID {scan_id} no fue encontrado.",
        )

    target = job.params.get("target", "Objetivo No Especificado")
    findings = resolve_vulnscan_findings(job, queue)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    top_items: list[TopRiskItem] = []

    for f in findings:
        sev = (f.severity or "info").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1

    total = len(findings)
    total_non_zero = total if total > 0 else 1

    heatmap = SeverityHeatmap(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        total=total,
        critical_pct=round((counts["critical"] / total_non_zero) * 100, 1),
        high_pct=round((counts["high"] / total_non_zero) * 100, 1),
        medium_pct=round((counts["medium"] / total_non_zero) * 100, 1),
        low_pct=round((counts["low"] / total_non_zero) * 100, 1),
        info_pct=round((counts["info"] / total_non_zero) * 100, 1),
    )

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda x: sev_rank.get(x.severity.lower(), 5))

    rank = 1
    for f in sorted_findings[:5]:
        b_impact = f.description or "Riesgo potencial de compromiso o filtración de componentes en el activo objetivo."
        top_items.append(
            TopRiskItem(
                rank=rank,
                template_id=f.template_id,
                name=f.name,
                severity=f.severity.upper(),
                host=f.host or target,
                business_impact=b_impact[:160] + ("..." if len(b_impact) > 160 else ""),
            )
        )
        rank += 1

    exec_summary, business_impact_narrative = _generate_business_impact_narrative(
        target, counts["critical"], counts["high"], total
    )

    overall_risk = _calculate_overall_risk(counts["critical"], counts["high"], counts["medium"])

    report_data = ExecutiveReportData(
        scan_id=str(scan_id),
        target=target,
        scan_type=job.job_type.value,
        generated_by=user_info.get("username", "Director de TI"),
        overall_risk_level=overall_risk,
        executive_summary=exec_summary,
        business_impact_narrative=business_impact_narrative,
        heatmap=heatmap,
        top_risks=top_items,
    )

    generator = ExecutiveReportGenerator(report_data)
    pdf_bytes = generator.generate()

    audit_log = getattr(request.app.state, "audit_log", None)
    if audit_log is not None:
        await audit_log.record(
            user=user_info.get("username", "system"),
            action="report.executive_generated",
            resource=f"scan:{scan_id}",
            metadata={"template_version": report_data.template_version, "target": target},
        )

    filename = f"reporte_ejecutivo_{scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Report-Template-Version": report_data.template_version,
        },
    )


@router.post("/executive", response_class=Response)
async def generate_custom_executive_report_pdf(
    body: ExecutiveReportData,
    request: Request,
    user_info: dict = Depends(require_mfa_admin),
) -> Response:
    """Genera un reporte ejecutivo en PDF a partir de datos explícitos (HU-023)."""
    generator = ExecutiveReportGenerator(body)
    pdf_bytes = generator.generate()

    audit_log = getattr(request.app.state, "audit_log", None)
    if audit_log is not None:
        await audit_log.record(
            user=user_info.get("username", "system"),
            action="report.custom_executive_generated",
            resource=f"scan:{body.scan_id}",
            metadata={"template_version": body.template_version, "target": body.target},
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="reporte_ejecutivo_{body.scan_id}.pdf"',
            "X-Report-Template-Version": body.template_version,
        },
    )


# ── Endpoints del Reporte Técnico (HU-024 / RF-008) ───────────────────────────


@router.get("/technical/{scan_id}", response_class=Response)
async def export_technical_report(
    scan_id: UUID,
    request: Request,
    format: str = Query(default="pdf", pattern="^(pdf|html)$", description="Formato del reporte: pdf o html"),
    queue: JobQueue = Depends(get_job_queue),
    user_info: dict = Depends(require_mfa_admin),
) -> Response:
    """Genera y descarga el reporte técnico detallado en PDF o HTML (HU-024).

    Incluye evidencias PoC, identificadores CVE, comandos y pasos de remediación.
    Protegido por autenticación MFA. Cumple SLA < 10 s (RNF-005).
    """
    job = queue.get_job(scan_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Escaneo con ID {scan_id} no fue encontrado.",
        )

    target = job.params.get("target", "Objetivo No Especificado")
    findings = resolve_vulnscan_findings(job, queue)
    tech_findings = [_generate_technical_finding_details(f, idx + 1) for idx, f in enumerate(findings)]

    report_data = TechnicalReportData(
        scan_id=str(scan_id),
        target=target,
        scan_type=job.job_type.value,
        generated_by=user_info.get("username", "SysAdmin"),
        total_findings=len(tech_findings),
        findings=tech_findings,
    )

    generator = TechnicalReportGenerator(report_data)

    audit_log = getattr(request.app.state, "audit_log", None)
    if audit_log is not None:
        await audit_log.record(
            user=user_info.get("username", "system"),
            action="report.technical_generated",
            resource=f"scan:{scan_id}",
            metadata={"format": format, "template_version": report_data.template_version, "target": target},
        )

    if format.lower() == "html":
        html_content = generator.generate_html()
        filename = f"reporte_tecnico_{scan_id}.html"
        return Response(
            content=html_content,
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Report-Template-Version": report_data.template_version,
            },
        )

    pdf_bytes = generator.generate_pdf()
    filename = f"reporte_tecnico_{scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Report-Template-Version": report_data.template_version,
        },
    )


@router.post("/technical", response_class=Response)
async def generate_custom_technical_report(
    body: TechnicalReportData,
    request: Request,
    format: str = Query(default="pdf", pattern="^(pdf|html)$"),
    user_info: dict = Depends(require_mfa_admin),
) -> Response:
    """Genera un reporte técnico en PDF o HTML a partir de datos explícitos (HU-024)."""
    generator = TechnicalReportGenerator(body)

    audit_log = getattr(request.app.state, "audit_log", None)
    if audit_log is not None:
        await audit_log.record(
            user=user_info.get("username", "system"),
            action="report.custom_technical_generated",
            resource=f"scan:{body.scan_id}",
            metadata={"format": format, "template_version": body.template_version, "target": body.target},
        )

    if format.lower() == "html":
        html_content = generator.generate_html()
        return Response(
            content=html_content,
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="reporte_tecnico_{body.scan_id}.html"',
                "X-Report-Template-Version": body.template_version,
            },
        )

    pdf_bytes = generator.generate_pdf()
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="reporte_tecnico_{body.scan_id}.pdf"',
            "X-Report-Template-Version": body.template_version,
        },
    )


# ── Endpoints de Persistencia Cifrada (HU-007) ─────────────────────────────


@router.post("", status_code=201, response_model=ReportRecord)
async def create_report(
    body: ReportCreate,
    store: EncryptedPersistenceService = Depends(get_persistence),
) -> ReportRecord:
    """Persiste un reporte cifrando contenido sensible en reposo."""
    return await store.save_report(body)


@router.get("", response_model=list[ReportRecord])
async def list_reports(
    store: EncryptedPersistenceService = Depends(get_persistence),
) -> list[ReportRecord]:
    return await store.list_reports(decrypt=True)


@router.get("/{report_id}", response_model=ReportRecord)
async def get_report(
    report_id: UUID,
    store: EncryptedPersistenceService = Depends(get_persistence),
) -> ReportRecord:
    record = await store.get_report(report_id, decrypt=True)
    if record is None:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    return record
