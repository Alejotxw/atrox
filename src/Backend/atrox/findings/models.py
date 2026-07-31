"""Modelos del marcado manual de falsos positivos (HU-022)."""

from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from atrox.scanner.models import VulnFinding


class MarkFalsePositiveRequest(BaseModel):
    """Payload para marcar un hallazgo como falso positivo."""

    finding: VulnFinding
    finding_id: str | None = Field(
        default=None,
        description=(
            "Identificador externo del hallazgo. Si se omite, se usa "
            "finding.template_id — debe coincidir con el criterio usado por "
            "GET /api/scans/{scan_id} para excluirlo (HU-010)."
        ),
    )
    reason: str | None = Field(default=None, description="Motivo opcional del marcado")


class FalsePositiveMark(BaseModel):
    """Registro persistente de un hallazgo marcado manualmente como falso positivo."""

    id: UUID = Field(default_factory=uuid4)
    scan_id: str
    finding_id: str
    matched_at: str = Field(description="Desambigua hallazgos que comparten finding_id en el mismo scan")
    finding: VulnFinding
    user: str
    reason: str | None = None
    marked_at: datetime


class FalsePositiveMarkResponse(BaseModel):
    """Respuesta al marcar un hallazgo: confirmación con usuario y timestamp."""

    id: UUID
    scan_id: str
    finding_id: str
    user: str
    reason: str | None
    marked_at: datetime
