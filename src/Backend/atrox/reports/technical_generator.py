"""Generador de reportes técnicos y de mitigación en PDF y HTML para Atrox (HU-024 / RF-008 / RNF-005).

Produce reportes detallados orientados a SysAdmins con evidencias PoC, identificadores CVE,
comandos de parcheo y pasos exactos de remediación.
"""

import html
import io
import time
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from atrox.reports.models import TEMPLATE_VERSION, TechnicalReportData


def _make_technical_page_callback(template_version: str, target: str):
    def add_header_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(colors.HexColor("#4A5568"))

        if doc.page > 1:
            canvas.drawString(36, 762, f"ATROX — Reporte Técnico de Remediación | Objetivo: {target}")
            canvas.setStrokeColor(colors.HexColor("#E2E8F0"))
            canvas.setLineWidth(0.5)
            canvas.line(36, 756, 576, 756)

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#718096"))
        canvas.drawString(
            36,
            30,
            f"CONFIDENCIAL — Reporte Técnico para SysAdmins | Plantilla v{template_version}",
        )
        canvas.drawRightString(576, 30, f"Página {doc.page}")
        canvas.setStrokeColor(colors.HexColor("#E2E8F0"))
        canvas.setLineWidth(0.5)
        canvas.line(36, 42, 576, 42)

        canvas.restoreState()

    return add_header_footer


class TechnicalReportGenerator:
    """Generador de reportes técnicos detallados en PDF y HTML."""

    SEVERITY_COLORS = {
        "CRITICAL": colors.HexColor("#9B2C2C"),
        "HIGH": colors.HexColor("#C53030"),
        "MEDIUM": colors.HexColor("#DD6B20"),
        "LOW": colors.HexColor("#D69E2E"),
        "INFO": colors.HexColor("#3182CE"),
        "UNKNOWN": colors.HexColor("#718096"),
    }

    SEVERITY_HEX = {
        "CRITICAL": "#9B2C2C",
        "HIGH": "#C53030",
        "MEDIUM": "#DD6B20",
        "LOW": "#D69E2E",
        "INFO": "#3182CE",
        "UNKNOWN": "#718096",
    }

    def __init__(self, data: TechnicalReportData):
        self.data = data
        self.template_version = data.template_version or TEMPLATE_VERSION

    def generate_pdf(self) -> bytes:
        """Genera el reporte técnico en formato PDF y retorna los bytes en memoria."""
        start_time = time.perf_counter()
        buffer = io.BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=40,
            bottomMargin=50,
            title=f"Reporte Técnico Atrox - {self.data.target}",
            author="Atrox Security Framework",
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "TechTitle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#1A202C"),
            spaceAfter=4,
        )

        subtitle_style = ParagraphStyle(
            "TechSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#7A1C3E"),
            spaceAfter=10,
        )

        section_heading = ParagraphStyle(
            "TechSectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#2D3748"),
            spaceBefore=12,
            spaceAfter=6,
        )

        body_style = ParagraphStyle(
            "TechBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#2D3748"),
            spaceAfter=6,
        )

        code_box_style = ParagraphStyle(
            "TechCodeBox",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#E2E8F0"),
            backColor=colors.HexColor("#0F172A"),
            borderColor=colors.HexColor("#334155"),
            borderWidth=1,
            borderPadding=6,
            spaceAfter=6,
        )

        elements = []

        # 1. Encabezado
        elements.append(Paragraph("ATROX PENTESTING FRAMEWORK", subtitle_style))
        elements.append(Paragraph("Reporte Técnico de Remediación y PoC", title_style))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#7A1C3E"), spaceBefore=2, spaceAfter=10))

        # Meta-tabla
        meta_data_table = [
            [
                Paragraph("<b>Objetivo Evaluado:</b>", body_style),
                Paragraph(self.data.target, body_style),
                Paragraph("<b>Total Hallazgos:</b>", body_style),
                Paragraph(f"<b>{self.data.total_findings or len(self.data.findings)}</b>", body_style),
            ],
            [
                Paragraph("<b>ID de Escaneo:</b>", body_style),
                Paragraph(str(self.data.scan_id), body_style),
                Paragraph("<b>Plantilla de Reporte:</b>", body_style),
                Paragraph(f"v{self.template_version}", body_style),
            ],
            [
                Paragraph("<b>Destinatario:</b>", body_style),
                Paragraph(self.data.generated_by, body_style),
                Paragraph("<b>Fecha de Generación:</b>", body_style),
                Paragraph(self.data.generated_at, body_style),
            ],
        ]

        meta_table = Table(meta_data_table, colWidths=[110, 160, 130, 140])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        # Resumen del entorno
        elements.append(Paragraph("1. Resumen Técnico del Entorno", section_heading))
        elements.append(Paragraph(self.data.environment_summary, body_style))
        elements.append(Spacer(1, 8))

        # 2. Lista de Hallazgos Técnicos
        elements.append(Paragraph("2. Detalles de Vulnerabilidades, PoC y Comandos de Remediación", section_heading))

        if not self.data.findings:
            elements.append(Paragraph("No se encontraron vulnerabilidades para el objetivo en este escaneo.", body_style))
        else:
            for item in self.data.findings:
                sev_upper = item.severity.upper()
                sev_color = self.SEVERITY_COLORS.get(sev_upper, colors.HexColor("#718096"))
                cves_str = ", ".join(item.cve_ids) if item.cve_ids else "Sin CVE asociado"

                finding_elements = []

                # Título del hallazgo
                finding_header = f"<b>Hallazgo #{item.item_id}: {item.name}</b>"
                finding_elements.append(Paragraph(finding_header, ParagraphStyle("FHeader", parent=section_heading, fontSize=11, spaceBefore=6, spaceAfter=4)))

                # Tabla de resumen del hallazgo
                info_table_data = [
                    [
                        Paragraph("<b>Template ID:</b>", body_style),
                        Paragraph(item.template_id, body_style),
                        Paragraph("<b>Severidad:</b>", body_style),
                        Paragraph(f"<b><font color='{sev_color.hexval()}'>{sev_upper}</font></b>", body_style),
                    ],
                    [
                        Paragraph("<b>Activo Afectado:</b>", body_style),
                        Paragraph(item.host, body_style),
                        Paragraph("<b>Identificadores CVE:</b>", body_style),
                        Paragraph(f"<font color='#3182CE'>{cves_str}</font>", body_style),
                    ],
                    [
                        Paragraph("<b>Ubicación Matched:</b>", body_style),
                        Paragraph(item.matched_at or item.host, body_style),
                        Paragraph("<b>Etiquetas:</b>", body_style),
                        Paragraph(", ".join(item.tags) if item.tags else "-", body_style),
                    ],
                ]

                it_table = Table(info_table_data, colWidths=[100, 170, 110, 160])
                it_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
                            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
                            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                            ("PADDING", (0, 0), (-1, -1), 4),
                        ]
                    )
                )
                finding_elements.append(it_table)
                finding_elements.append(Spacer(1, 4))

                # Descripción
                if item.description:
                    finding_elements.append(Paragraph("<b>Descripción Técnica:</b>", body_style))
                    finding_elements.append(Paragraph(item.description, body_style))

                # Evidencia / PoC (Criterio de Aceptación 1)
                if item.poc_evidence:
                    finding_elements.append(Paragraph("<b>Evidencia de Explotación (Proof of Concept - PoC):</b>", body_style))
                    escaped_poc = item.poc_evidence.replace("\n", "<br/>")
                    finding_elements.append(Paragraph(escaped_poc, code_box_style))

                # Pasos de remediación / mitigación
                if item.remediation_steps:
                    finding_elements.append(Paragraph("<b>Pasos de Remediación y Mitigación:</b>", body_style))
                    finding_elements.append(Paragraph(item.remediation_steps, body_style))

                # Comandos de consola
                if item.remediation_commands:
                    finding_elements.append(Paragraph("<b>Comandos de Consola para Parcheo/Verificación:</b>", body_style))
                    cmd_block = "<br/>".join([f"$ {cmd}" for cmd in item.remediation_commands])
                    finding_elements.append(Paragraph(cmd_block, code_box_style))

                # Referencias
                if item.references:
                    refs_str = "<br/>".join([f"• <font color='#3182CE'>{r}</font>" for r in item.references[:3]])
                    finding_elements.append(Paragraph(f"<b>Referencias y Documentación:</b><br/>{refs_str}", body_style))

                finding_elements.append(Spacer(1, 10))
                finding_elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E0"), spaceBefore=2, spaceAfter=8))

                elements.append(KeepTogether(finding_elements))

        page_callback = _make_technical_page_callback(self.template_version, self.data.target)
        doc.build(elements, onFirstPage=page_callback, onLaterPages=page_callback)

        pdf_bytes = buffer.getvalue()
        buffer.close()

        elapsed = time.perf_counter() - start_time
        if elapsed > 10.0:
            raise RuntimeError(f"Generación de PDF técnico violó SLA: tomó {elapsed:.2f}s (máximo 10s)")

        return pdf_bytes

    def generate_html(self) -> str:
        """Genera el reporte técnico en formato HTML auto-contenido (HU-024 / RF-008)."""
        start_time = time.perf_counter()

        findings_html = []
        for item in self.data.findings:
            sev_upper = item.severity.upper()
            sev_color = self.SEVERITY_HEX.get(sev_upper, "#718096")
            cves_html = "".join([f'<span class="cve-tag">{html.escape(c)}</span>' for c in item.cve_ids]) if item.cve_ids else '<span class="text-gray-500">Sin CVE</span>'
            tags_html = ", ".join([html.escape(t) for t in item.tags]) if item.tags else "-"

            poc_section = ""
            if item.poc_evidence:
                poc_section = f"""
                <div class="section-block">
                    <h4>Evidencia de Explotación (Proof of Concept - PoC)</h4>
                    <pre className="code-block"><code>{html.escape(item.poc_evidence)}</code></pre>
                </div>
                """

            commands_section = ""
            if item.remediation_commands:
                cmds = "\n".join([f"$ {c}" for c in item.remediation_commands])
                commands_section = f"""
                <div class="section-block">
                    <h4>Comandos de Consola para Parcheo/Verificación</h4>
                    <pre className="code-block console"><code>{html.escape(cmds)}</code></pre>
                </div>
                """

            remediation_section = ""
            if item.remediation_steps:
                remediation_section = f"""
                <div class="section-block">
                    <h4>Pasos de Remediación y Mitigación</h4>
                    <p>{html.escape(item.remediation_steps)}</p>
                </div>
                """

            refs_section = ""
            if item.references:
                refs_list = "".join([f'<li><a href="{html.escape(r)}" target="_blank">{html.escape(r)}</a></li>' for r in item.references[:4]])
                refs_section = f"""
                <div class="section-block">
                    <h4>Referencias</h4>
                    <ul class="ref-list">{refs_list}</ul>
                </div>
                """

            finding_card = f"""
            <div class="card finding-card">
                <div class="card-header">
                    <h3>#{item.item_id} — {html.escape(item.name)}</h3>
                    <span class="badge" style="background-color: {sev_color};">{sev_upper}</span>
                </div>
                <div class="meta-grid">
                    <div><strong>Template ID:</strong> {html.escape(item.template_id)}</div>
                    <div><strong>Activo Afectado:</strong> {html.escape(item.host)}</div>
                    <div><strong>Ubicación:</strong> {html.escape(item.matched_at or item.host)}</div>
                    <div><strong>CVEs:</strong> {cves_html}</div>
                    <div className="col-span-2"><strong>Etiquetas:</strong> {tags_html}</div>
                </div>
                <div className="section-block">
                    <h4>Descripción Técnica</h4>
                    <p>{html.escape(item.description or "Sin descripción detallada.")}</p>
                </div>
                {poc_section}
                {remediation_section}
                {commands_section}
                {refs_section}
            </div>
            """
            findings_html.append(finding_card)

        if not findings_html:
            findings_html.append('<div class="card"><p>No se encontraron hallazgos técnicos registrados en este escaneo.</p></div>')

        html_document = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte Técnico Atrox - {html.escape(self.data.target)}</title>
    <style>
        :root {{
            --bg-color: #0F172A;
            --card-bg: #1E293B;
            --text-color: #E2E8F0;
            --border-color: #334155;
            --primary: #7A1C3E;
            --accent: #3182CE;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid var(--primary);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .header h1 {{
            margin: 0 0 8px 0;
            color: #FFFFFF;
            font-size: 26px;
        }}
        .header .subtitle {{
            color: #94A3B8;
            font-size: 14px;
            font-weight: 600;
        }}
        .meta-summary {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 24px;
        }}
        .meta-summary div {{
            font-size: 13px;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 12px;
            margin-bottom: 16px;
        }}
        .card-header h3 {{
            margin: 0;
            color: #FFFFFF;
            font-size: 18px;
        }}
        .badge {{
            color: #FFFFFF;
            font-weight: bold;
            font-size: 11px;
            padding: 4px 10px;
            border-radius: 4px;
            letter-spacing: 0.5px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            background: #0B1121;
            padding: 12px;
            border-radius: 6px;
            font-size: 13px;
            margin-bottom: 16px;
        }}
        .section-block {{
            margin-top: 14px;
        }}
        .section-block h4 {{
            margin: 0 0 6px 0;
            font-size: 13px;
            color: #94A3B8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        pre.code-block {{
            background: #0B1121;
            border: 1px solid #334155;
            color: #38BDF8;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: "Courier New", Courier, monospace;
            font-size: 13px;
            margin: 4px 0;
        }}
        pre.console {{
            color: #4ADE80;
        }}
        .cve-tag {{
            background: #1E3A8A;
            color: #93C5FD;
            font-size: 11px;
            font-weight: bold;
            padding: 2px 6px;
            border-radius: 3px;
            margin-right: 4px;
        }}
        .ref-list {{
            margin: 4px 0;
            padding-left: 20px;
            font-size: 13px;
        }}
        .ref-list a {{
            color: var(--accent);
            text-decoration: none;
        }}
        .ref-list a:hover {{
            text-decoration: underline;
        }}
        .footer {{
            margin-top: 40px;
            border-top: 1px solid var(--border-color);
            padding-top: 16px;
            font-size: 12px;
            color: #64748B;
            display: flex;
            justify-content: space-between;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="subtitle">ATROX PENTESTING FRAMEWORK</div>
            <h1>Reporte Técnico de Remediación y PoC</h1>
        </div>

        <div class="meta-summary">
            <div><strong>Objetivo:</strong> {html.escape(self.data.target)}</div>
            <div><strong>ID de Escaneo:</strong> {html.escape(str(self.data.scan_id))}</div>
            <div><strong>Total Hallazgos:</strong> {self.data.total_findings or len(self.data.findings)}</div>
            <div><strong>Versión Plantilla:</strong> v{html.escape(self.template_version)}</div>
        </div>

        <div class="card">
            <h3>Resumen Técnico del Entorno</h3>
            <p>{html.escape(self.data.environment_summary)}</p>
        </div>

        <h2>Detalle de Vulnerabilidades, Evidencias (PoC) y Mitigación</h2>
        {"".join(findings_html)}

        <div class="footer">
            <div>CONFIDENCIAL — Reporte Técnico para SysAdmins | Atrox Framework</div>
            <div>Plantilla v{html.escape(self.template_version)} | Generado: {html.escape(self.data.generated_at)}</div>
        </div>
    </div>
</body>
</html>
"""

        elapsed = time.perf_counter() - start_time
        if elapsed > 10.0:
            raise RuntimeError(f"Generación de HTML técnico violó SLA: tomó {elapsed:.2f}s (máximo 10s)")

        return html_document
