"""Router REST de generación y exportación de reportes ejecutivos en PDF (HU-023).

Ruta protegida por MFA:
- `GET /api/reports/executive/{scan_id}`: Genera y descarga el PDF ejecutivo.
- `POST /api/reports/executive`: Genera un PDF ejecutivo a partir de datos explícitos.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from atrox.api.jobs import get_job_queue
from atrox.queue.service import JobQueue
from atrox.reports.generator import ExecutiveReportGenerator
from atrox.reports.models import ExecutiveReportData, SeverityHeatmap, TopRiskItem
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


@router.get("/executive/{scan_id}", response_class=Response)
async def export_executive_report_pdf(
    scan_id: UUID,
    request: Request,
    queue: JobQueue = Depends(get_job_queue),
    user_info: dict = Depends(require_mfa_admin),
) -> Response:
    """Genera y descarga el reporte ejecutivo en PDF para un escaneo específico (HU-023).

    Protegido por autenticación MFA (RF-007 / RNF-002). Cumple con tiempo de
    respuesta SLA < 10 s (RNF-005).
    """
    job = queue.get_job(scan_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Escaneo con ID {scan_id} no fue encontrado.",
        )

    target = job.params.get("target", "Objetivo No Especificado")
    raw_findings = []
    if job.result and isinstance(job.result, dict):
        raw_findings = job.result.get("findings", [])

    findings = [VulnFinding(**f) if isinstance(f, dict) else f for f in raw_findings]

    # Conteo por severidad
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    top_items: list[TopRiskItem] = []

    for idx, f in enumerate(findings):
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

    # Ordenar hallazgos para top riesgos (critical -> high -> medium -> low)
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

    # Registrar auditoría si está disponible
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
