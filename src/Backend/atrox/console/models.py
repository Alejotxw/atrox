"""Modelos de eventos de log de escaneo (HU-020)."""

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class LogSeverity(str, Enum):
    """Severidad de una línea de consola."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ScanLogEvent(BaseModel):
    """Evento de log emitido por el motor de escaneo hacia la UI."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    module: str = Field(..., min_length=1, max_length=64)
    severity: LogSeverity = LogSeverity.INFO
    message: str = Field(..., min_length=1, max_length=4000)
    job_id: UUID | None = None
