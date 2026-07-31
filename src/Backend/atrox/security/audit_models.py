from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AuditEventCreate(BaseModel):
    user: str = Field(..., min_length=1, max_length=128)
    action: str = Field(..., min_length=1, max_length=128)
    resource: str = Field(..., min_length=1, max_length=256)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditEvent(BaseModel):
    id: UUID
    timestamp: datetime
    user: str
    action: str
    resource: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class SignedAuditEntry(BaseModel):
    id: UUID
    timestamp: datetime
    user: str
    action: str
    resource: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    signature: str


class AuditLogQueryResult(BaseModel):
    total: int
    verified: int
    tampered: int
    entries: list[SignedAuditEntry]


class TamperDetectedError(ValueError):
    """Una o más entradas del log presentan firma inválida (posible alteración)."""
