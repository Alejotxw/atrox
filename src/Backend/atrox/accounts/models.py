"""Modelos de cuentas de usuario creadas al aprobar una solicitud de acceso."""

from datetime import UTC, datetime
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AccountStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DELETED = "deleted"


class ModerationNoteKind(str, Enum):
    WARNING = "warning"
    REPORT = "report"


class ModerationNote(BaseModel):
    """Advertencia o reporte por uso indebido, registrado por el super admin."""

    id: UUID = Field(default_factory=uuid4)
    kind: ModerationNoteKind
    reason: str
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Account(BaseModel):
    """Cuenta de usuario con acceso al panel operativo (creada al aprobar una solicitud)."""

    id: UUID = Field(default_factory=uuid4)
    username: str
    # Hash de una sola vía (scrypt, ver security/password_hasher.py) — no se
    # registra en SENSITIVE_FIELDS["account"]: cifrarlo con AES-256-GCM
    # (reversible) no aporta seguridad sobre un hash ya irreversible.
    password_hash: str
    full_name: str
    email: str
    organization: str
    role: str
    status: AccountStatus = AccountStatus.ACTIVE
    access_request_id: UUID | None = None
    moderation_notes: list[ModerationNote] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AccountPublic(BaseModel):
    """Vista de cuenta sin `password_hash`, para listados y respuestas administrativas."""

    id: UUID
    username: str
    full_name: str
    email: str
    organization: str
    role: str
    status: AccountStatus
    access_request_id: UUID | None
    moderation_notes: list[ModerationNote]
    created_at: datetime


class AccountListResult(BaseModel):
    total: int
    accounts: list[AccountPublic]


class ApproveAccessRequestResponse(BaseModel):
    """Respuesta al aprobar: la contraseña temporal se muestra UNA sola vez."""

    account: AccountPublic
    temporary_password: str


class ModerationActionRequest(BaseModel):
    """Payload para advertir o reportar una cuenta por uso fraudulento."""

    reason: str = Field(min_length=3, max_length=500)
