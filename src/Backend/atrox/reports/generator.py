"""Generador de reportes ejecutivos en PDF para Atrox (HU-023 / RF-007 / RNF-005).

Utiliza ReportLab para compilar en memoria una plantilla versionada (v1.0.0)
diseñada para comunicación de criticidad e impacto de negocio a Directores de TI y
stakeholders no técnicos.
"""

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

from atrox.reports.models import ExecutiveReportData, TEMPLATE_VERSION


class NumberedCanvas:
    """Canvas personalizado para incluir pie de página con número de página y versión."""

    def __init__(self, *args, **kwargs):
        pass


def _make_page_callback(template_version: str, target: str):
    def add_header_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(colors.HexColor("#4A5568"))

        # Encabezado secundario en páginas 2+
        if doc.page > 1:
            canvas.drawString(36, 762, f"ATROX — Reporte Ejecutivo de Seguridad | Objetivo: {target}")
            canvas.setStrokeColor(colors.HexColor("#E2E8F0"))
            canvas.setLineWidth(0.5)
            canvas.line(36, 756, 576, 756)

        # Pie de página en todas las páginas
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#718096"))
        canvas.drawString(
            36,
            30,
            f"CONFIDENCIAL — Generado por Atrox Pentesting Framework | Plantilla v{template_version}",
        )
        canvas.drawRightString(576, 30, f"Página {doc.page}")
        canvas.setStrokeColor(colors.HexColor("#E2E8F0"))
        canvas.setLineWidth(0.5)
        canvas.line(36, 42, 576, 42)

        canvas.restoreState()

    return add_header_footer


class ExecutiveReportGenerator:
    """Generador de PDF para reportes ejecutivos resumidos."""

    SEVERITY_COLORS = {
        "CRITICAL": colors.HexColor("#9B2C2C"),
        "HIGH": colors.HexColor("#C53030"),
        "MEDIUM": colors.HexColor("#DD6B20"),
        "LOW": colors.HexColor("#D69E2E"),
        "INFO": colors.HexColor("#3182CE"),
        "UNKNOWN": colors.HexColor("#718096"),
    }

    RISK_LEVEL_COLORS = {
        "CRÍTICO": colors.HexColor("#9B2C2C"),
        "ALTO": colors.HexColor("#C53030"),
        "MEDIO": colors.HexColor("#DD6B20"),
        "BAJO": colors.HexColor("#319795"),
    }

    def __init__(self, data: ExecutiveReportData):
        self.data = data
        self.template_version = data.template_version or TEMPLATE_VERSION

    def generate(self) -> bytes:
        """Compila el reporte ejecutivo a PDF en memoria y retorna los bytes."""
        start_time = time.perf_counter()
        buffer = io.BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=40,
            bottomMargin=50,
            title=f"Reporte Ejecutivo Atrox - {self.data.target}",
            author="Atrox AI Framework",
        )

        styles = getSampleStyleSheet()

        # Estilos personalizados
        title_style = ParagraphStyle(
            "ExecutiveTitle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#1A202C"),
            spaceAfter=4,
        )

        subtitle_style = ParagraphStyle(
            "ExecutiveSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#3182CE"),
            spaceAfter=12,
        )

        section_heading = ParagraphStyle(
            "ExecutiveSectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#2D3748"),
            spaceBefore=12,
            spaceAfter=8,
        )

        body_style = ParagraphStyle(
            "ExecutiveBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#2D3748"),
            spaceAfter=8,
        )

        table_header_style = ParagraphStyle(
            "TableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=11,
            textColor=colors.white,
        )

        table_cell_style = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#2D3748"),
        )

        table_cell_bold = ParagraphStyle(
            "TableCellBold",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#1A202C"),
        )

        elements = []

        # 1. Encabezado principal
        elements.append(Paragraph("ATROX PENTESTING FRAMEWORK", subtitle_style))
        elements.append(Paragraph("Reporte Ejecutivo de Seguridad", title_style))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#3182CE"), spaceBefore=2, spaceAfter=10))

        # Meta-tabla (Target, ID de Escaneo, Audiencia, Nivel de Riesgo Global)
        risk_color = self.RISK_LEVEL_COLORS.get(self.data.overall_risk_level.upper(), colors.HexColor("#C53030"))
        
        meta_data_table = [
            [
                Paragraph("<b>Objetivo Evaluado:</b>", body_style),
                Paragraph(self.data.target, body_style),
                Paragraph("<b>Nivel de Riesgo Global:</b>", body_style),
                Paragraph(f"<font color='{risk_color.hexval()}'><b>{self.data.overall_risk_level}</b></font>", body_style),
            ],
            [
                Paragraph("<b>ID de Escaneo:</b>", body_style),
                Paragraph(str(self.data.scan_id), body_style),
                Paragraph("<b>Plantilla de Reporte:</b>", body_style),
                Paragraph(f"v{self.template_version}", body_style),
            ],
            [
                Paragraph("<b>Audiencia Objetivo:</b>", body_style),
                Paragraph(self.data.generated_by, body_style),
                Paragraph("<b>Fecha de Generación:</b>", body_style),
                Paragraph(self.data.generated_at, body_style),
            ],
        ]

        meta_table = Table(meta_data_table, colWidths=[110, 160, 130, 140])
        meta_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        elements.append(meta_table)
        elements.append(Spacer(1, 12))

        # 2. Resumen Ejecutivo e Impacto de Negocio
        elements.append(Paragraph("1. Resumen Ejecutivo e Impacto de Negocio", section_heading))
        elements.append(Paragraph(self.data.executive_summary, body_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(self.data.business_impact_narrative, body_style))
        elements.append(Spacer(1, 10))

        # 3. Heatmap de Severidad (Criterio de Aceptación 2)
        elements.append(Paragraph("2. Heatmap y Distribución de Severidad", section_heading))
        
        hp = self.data.heatmap
        heatmap_data = [
            [
                Paragraph("Nivel de Severidad", table_header_style),
                Paragraph("Hallazgos", table_header_style),
                Paragraph("Porcentaje", table_header_style),
                Paragraph("Representación Visual", table_header_style),
            ],
            [
                Paragraph("<b>CRÍTICA</b>", ParagraphStyle("Crit", parent=table_cell_style, textColor=colors.HexColor("#9B2C2C"))),
                Paragraph(str(hp.critical), table_cell_bold),
                Paragraph(f"{hp.critical_pct:.1f}%", table_cell_style),
                Paragraph("█" * int(hp.critical_pct // 5), ParagraphStyle("BarC", parent=table_cell_style, textColor=colors.HexColor("#9B2C2C"))),
            ],
            [
                Paragraph("<b>ALTA</b>", ParagraphStyle("High", parent=table_cell_style, textColor=colors.HexColor("#C53030"))),
                Paragraph(str(hp.high), table_cell_bold),
                Paragraph(f"{hp.high_pct:.1f}%", table_cell_style),
                Paragraph("█" * int(hp.high_pct // 5), ParagraphStyle("BarH", parent=table_cell_style, textColor=colors.HexColor("#C53030"))),
            ],
            [
                Paragraph("<b>MEDIA</b>", ParagraphStyle("Med", parent=table_cell_style, textColor=colors.HexColor("#DD6B20"))),
                Paragraph(str(hp.medium), table_cell_bold),
                Paragraph(f"{hp.medium_pct:.1f}%", table_cell_style),
                Paragraph("█" * int(hp.medium_pct // 5), ParagraphStyle("BarM", parent=table_cell_style, textColor=colors.HexColor("#DD6B20"))),
            ],
            [
                Paragraph("<b>BAJA</b>", ParagraphStyle("Low", parent=table_cell_style, textColor=colors.HexColor("#D69E2E"))),
                Paragraph(str(hp.low), table_cell_bold),
                Paragraph(f"{hp.low_pct:.1f}%", table_cell_style),
                Paragraph("█" * int(hp.low_pct // 5), ParagraphStyle("BarL", parent=table_cell_style, textColor=colors.HexColor("#D69E2E"))),
            ],
            [
                Paragraph("<b>INFORMATIVA</b>", ParagraphStyle("Info", parent=table_cell_style, textColor=colors.HexColor("#3182CE"))),
                Paragraph(str(hp.info), table_cell_bold),
                Paragraph(f"{hp.info_pct:.1f}%", table_cell_style),
                Paragraph("█" * int(hp.info_pct // 5), ParagraphStyle("BarI", parent=table_cell_style, textColor=colors.HexColor("#3182CE"))),
            ],
            [
                Paragraph("<b>TOTAL</b>", table_cell_bold),
                Paragraph(f"<b>{hp.total}</b>", table_cell_bold),
                Paragraph("100.0%", table_cell_bold),
                Paragraph("-", table_cell_style),
            ],
        ]

        heatmap_table = Table(heatmap_data, colWidths=[120, 80, 90, 250])
        heatmap_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2D3748")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("ALIGN", (1, 0), (2, -1), "CENTER"),
                    ("PADDING", (0, 0), (-1, -1), 5),
                    ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#EDF2F7")),
                ]
            )
        )
        elements.append(heatmap_table)
        elements.append(Spacer(1, 14))

        # 4. Top Riesgos Prioritarios (Criterio de Aceptación 2)
        elements.append(Paragraph("3. Top Riesgos Prioritarios de Negocio", section_heading))

        top_risks_data = [
            [
                Paragraph("#", table_header_style),
                Paragraph("Vulnerabilidad / Riesgo", table_header_style),
                Paragraph("Severidad", table_header_style),
                Paragraph("Activo Afectado", table_header_style),
                Paragraph("Impacto de Negocio", table_header_style),
            ]
        ]

        if not self.data.top_risks:
            top_risks_data.append(
                [
                    Paragraph("1", table_cell_style),
                    Paragraph("Sin hallazgos de riesgo alto identificados", table_cell_style),
                    Paragraph("INFO", table_cell_style),
                    Paragraph(self.data.target, table_cell_style),
                    Paragraph("No se detectaron amenazas críticas durante el escaneo.", table_cell_style),
                ]
            )
        else:
            for item in self.data.top_risks[:5]:
                sev_upper = item.severity.upper()
                sev_color = self.SEVERITY_COLORS.get(sev_upper, colors.HexColor("#718096"))
                sev_p = Paragraph(
                    f"<b><font color='{sev_color.hexval()}'>{sev_upper}</font></b>",
                    table_cell_style,
                )
                top_risks_data.append(
                    [
                        Paragraph(str(item.rank), table_cell_bold),
                        Paragraph(f"<b>{item.name}</b><br/><font color='#718096'>{item.template_id}</font>", table_cell_style),
                        sev_p,
                        Paragraph(item.host or self.data.target, table_cell_style),
                        Paragraph(item.business_impact, table_cell_style),
                    ]
                )

        top_risks_table = Table(top_risks_data, colWidths=[30, 150, 75, 105, 180])
        top_risks_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A202C")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        elements.append(KeepTogether(top_risks_table))

        # Construcción del PDF
        page_callback = _make_page_callback(self.template_version, self.data.target)
        doc.build(elements, onFirstPage=page_callback, onLaterPages=page_callback)

        pdf_bytes = buffer.getvalue()
        buffer.close()

        elapsed = time.perf_counter() - start_time
        # Verificación del SLA (< 10 segundos según RNF-005)
        if elapsed > 10.0:
            raise RuntimeError(f"Generación de PDF violó SLA: tomó {elapsed:.2f}s (máximo 10s)")

        return pdf_bytes
