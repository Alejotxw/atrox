"""Modelos del agente de generación de payloads (HU-015)."""

from pydantic import BaseModel, Field

from atrox.scanner.models import VulnFinding

LAB_ONLY_DISCLAIMER = (
    "Uso exclusivo en entornos de laboratorio autorizados. Ejecutar estos "
    "payloads contra sistemas sin autorización explícita del propietario es "
    "ilegal y queda fuera del alcance de este framework."
)


class PayloadSuggestion(BaseModel):
    """Payload sugerido para una categoría de vulnerabilidad detectada."""

    category: str = Field(description="Categoría de vulnerabilidad (ej. sqli, xss, rce)")
    payload: str
    description: str


class PayloadGenerationRequest(BaseModel):
    """Payload de entrada: el hallazgo a analizar y su identificador."""

    finding: VulnFinding
    finding_id: str | None = Field(
        default=None,
        description=(
            "Identificador externo del hallazgo (ej. de una futura tabla de findings). "
            "Si se omite, se usa finding.template_id como identificador."
        ),
    )


class PayloadGenerationResult(BaseModel):
    """Salida estructurada del agente: payloads asociados a un finding_id."""

    finding_id: str
    service: str = Field(description="Servicio/tecnología inferida del hallazgo")
    category: str = Field(description="Categoría principal de vulnerabilidad detectada")
    suggestions: list[PayloadSuggestion]
    disclaimer: str = LAB_ONLY_DISCLAIMER
    generation_time_ms: float
    within_sla: bool = Field(description="True si generation_time_ms < 5000 (RNF-004)")
