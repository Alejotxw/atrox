"""Modelos de solicitudes de acceso enviadas desde la página pública (pre-login)."""

import re
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AccessRequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class AccessRequestCreate(BaseModel):
    """Payload enviado desde el formulario público de solicitud de acceso."""

    full_name: str = Field(min_length=2, max_length=200)
    email: str = Field(min_length=5, max_length=254)
    organization: str = Field(min_length=2, max_length=200)
    role: str = Field(min_length=2, max_length=100)
    reason: str = Field(min_length=10, max_length=2000)

    @field_validator("email")
    @classmethod
    def _validate_email_format(cls, value: str) -> str:
        if not _EMAIL_PATTERN.match(value):
            raise ValueError("Formato de correo inválido")
        return value


class AccessRequest(BaseModel):
    """Registro persistente de una solicitud de acceso."""

    id: UUID = Field(default_factory=uuid4)
    full_name: str
    email: str
    organization: str
    role: str
    reason: str
    status: AccessRequestStatus = AccessRequestStatus.PENDING
    reviewed_at: datetime | None = None
    review_reason: str | None = Field(
        default=None, description="Motivo opcional de rechazo, capturado por el administrador"
    )
    account_id: UUID | None = Field(default=None, description="Cuenta creada al aprobar, si aplica")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AccessRequestListResult(BaseModel):
    """Respuesta paginada-simple del listado administrativo de solicitudes."""

    total: int
    requests: list[AccessRequest]


class RejectAccessRequestRequest(BaseModel):
    """Payload opcional al rechazar una solicitud."""

    reason: str | None = Field(default=None, max_length=500)
