"""Modelos del agente de vectores de ataque (HU-014)."""

from pydantic import BaseModel, Field

from atrox.scanner.models import VulnFinding, VulnSeverity


class AttackVector(BaseModel):
    """Vector de ataque priorizado con cadena lógica y justificación."""

    rank: int = Field(..., ge=1, description="Prioridad (1 = mayor impacto)")
    vector_id: str
    name: str
    severity_score: float = Field(..., ge=0, le=10)
    finding_ids: list[str] = Field(description="Hallazgos correlacionados (template_id)")
    chain: list[str] = Field(description="Pasos encadenados del ataque")
    justification: str
    estimated_impact: str


class AttackVectorLLMPayload(BaseModel):
    """Esquema exacto que debe cumplir la respuesta cruda del LLM real
    (Ollama/Gemini) al pedir análisis de vectores de ataque — ver
    `atrox/ai/agents/vectors/llm_analyzer.py`. Solo pide los vectores; los
    campos agregados (total_findings, analysis_time_ms, within_sla) los
    calcula el servidor, no el LLM."""

    vectors: list[AttackVector]


class VectorAnalysisRequest(BaseModel):
    findings: list[VulnFinding] = Field(..., max_length=10)


class VectorAnalysisResult(BaseModel):
    vectors: list[AttackVector]
    total_findings: int
    analysis_time_ms: float
    within_sla: bool = Field(description="True si analysis_time_ms < 5000 (RNF-004)")
    source: str = Field(
        default="heuristic",
        description="'llm' si un modelo de IA real generó el análisis, 'heuristic' si fue el motor de reglas (fallback)",
    )
    model_used: str | None = Field(
        default=None, description="Nombre del modelo LLM que respondió, si source='llm'"
    )
