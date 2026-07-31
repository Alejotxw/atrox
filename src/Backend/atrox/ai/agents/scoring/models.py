"""Modelos del agente de scoring de confianza (HU-016)."""

from pydantic import BaseModel, Field

from atrox.scanner.models import VulnFinding


class ScoringRequest(BaseModel):
    """Payload de entrada: el hallazgo a evaluar y su identificador."""

    finding: VulnFinding
    finding_id: str | None = Field(
        default=None,
        description=(
            "Identificador externo del hallazgo. Si se omite, se usa "
            "finding.template_id como identificador."
        ),
    )
    threshold: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description=(
            "Override puntual del umbral configurado (ATROX_FP_SCORE_THRESHOLD) "
            "para esta evaluación."
        ),
    )


class ConfidenceScoreResult(BaseModel):
    """Salida estructurada: score de confianza 0-100 asociado a un finding_id."""

    finding_id: str
    score: int = Field(..., ge=0, le=100, description="Score de confianza (100 = muy confiable)")
    threshold: int = Field(..., ge=0, le=100, description="Umbral usado para esta clasificación")
    probable_fp: bool = Field(description="True si score < threshold")
    explanation: str = Field(description="Explicación breve de las señales que componen el score")
    generation_time_ms: float
    within_sla: bool = Field(description="True si generation_time_ms < 5000 (RNF-004)")
