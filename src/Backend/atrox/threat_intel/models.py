"""Modelos de dominio de inteligencia de amenazas (HU-005 / RF-010).

Catálogo de CVEs sincronizado desde la API NVD y estado de la última
sincronización. La descripción es el único campo textual libre y no se
clasifica como sensible (ADR-003): los CVEs son datos públicos ya conocidos.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class CveSyncStatusEnum(str, Enum):
    """Estado de una ejecución de sincronización con la API NVD."""

    OK = "ok"
    ERROR = "error"


class CVEEntry(BaseModel):
    """Representación de un CVE del catálogo de amenazas.

    Persiste CVE-ID, CVSS (score + severidad), descripción y fechas
    (publicado / última modificación) según criterios de HU-005.
    """

    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    description: str = ""
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    published_date: datetime
    last_modified_date: datetime | None = None


class CveSyncStatus(BaseModel):
    """Registro consultable de la última sincronización con NVD."""

    status: CveSyncStatusEnum
    last_attempt_at: datetime
    last_success_at: datetime | None = None
    cves_total: int = 0
    cves_added: int = 0
    cves_updated: int = 0
    last_error: str | None = None
