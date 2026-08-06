"""Modelos Pydantic para reportes ejecutivos (HU-023 / RF-007)."""

from datetime import datetime
from pydantic import BaseModel, Field

TEMPLATE_VERSION = "1.0.0"


class SeverityHeatmap(BaseModel):
    """Estadísticas y distribución del heatmap de severidad."""

    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)
    critical_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    high_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    medium_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    low_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    info_pct: float = Field(default=0.0, ge=0.0, le=100.0)


class TopRiskItem(BaseModel):
    """Vulnerabilidad de alta prioridad orientada a impacto de negocio."""

    rank: int
    template_id: str
    name: str
    severity: str
    host: str
    business_impact: str
    confidence_score: float | None = None
    remediation_priority: str = "Inmediata"


class ExecutiveReportData(BaseModel):
    """Datos estructurados requeridos para la plantilla del reporte ejecutivo."""

    scan_id: str
    target: str
    scan_type: str = "vulnscan"
    generated_at: str = Field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    generated_by: str = "Director de TI"
    template_version: str = TEMPLATE_VERSION
    overall_risk_level: str = "ALTO"
    executive_summary: str
    business_impact_narrative: str
    heatmap: SeverityHeatmap
    top_risks: list[TopRiskItem] = Field(default_factory=list)
