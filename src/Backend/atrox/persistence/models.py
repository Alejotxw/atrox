"""Modelos de persistencia para hallazgos, credenciales y reportes (HU-007)."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class FindingRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    job_id: UUID | None = None
    template_id: str = ""
    name: str
    severity: str = "unknown"
    host: str = ""
    matched_at: str = ""
    tags: list[str] = Field(default_factory=list)
    # Campos sensibles (cifrados en reposo)
    description: str | dict[str, Any] | None = None
    evidence: str | dict[str, Any] | None = None
    poc: str | dict[str, Any] | None = None
    raw_output: str | dict[str, Any] | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CredentialRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    username: str
    host: str = ""
    label: str = ""
    # Campos sensibles (cifrados en reposo)
    password: str | dict[str, Any] | None = None
    secret: str | dict[str, Any] | None = None
    token: str | dict[str, Any] | None = None
    private_key: str | dict[str, Any] | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReportRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    report_type: str = "technical"  # technical | executive
    job_id: UUID | None = None
    # Campos sensibles (cifrados en reposo)
    content: str | dict[str, Any] | None = None
    executive_summary: str | dict[str, Any] | None = None
    technical_details: str | dict[str, Any] | None = None
    body: str | dict[str, Any] | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class FindingCreate(BaseModel):
    name: str
    severity: str = "unknown"
    host: str = ""
    matched_at: str = ""
    template_id: str = ""
    tags: list[str] = Field(default_factory=list)
    job_id: UUID | None = None
    description: str | None = None
    evidence: str | None = None
    poc: str | None = None
    raw_output: str | None = None


class CredentialCreate(BaseModel):
    username: str
    host: str = ""
    label: str = ""
    password: str | None = None
    secret: str | None = None
    token: str | None = None
    private_key: str | None = None


class ReportCreate(BaseModel):
    title: str
    report_type: str = "technical"
    job_id: UUID | None = None
    content: str | None = None
    executive_summary: str | None = None
    technical_details: str | None = None
    body: str | None = None
