from enum import Enum

from pydantic import BaseModel, Field, field_validator

from atrox.scanner.validators import validate_port_range, validate_target


class ScanStatus(str, Enum):
    COMPLETED = "completed"
    UNREACHABLE = "unreachable"
    TIMEOUT = "timeout"
    ERROR = "error"


class VulnSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class DiscoveryScanRequest(BaseModel):
    target: str = Field(..., description="IP o FQDN del objetivo")
    port_range: str = Field(default="1-1024", description="Rango de puertos Nmap (ej. 80,443 o 1-1024)")

    @field_validator("target")
    @classmethod
    def check_target(cls, value: str) -> str:
        return validate_target(value)

    @field_validator("port_range")
    @classmethod
    def check_port_range(cls, value: str) -> str:
        return validate_port_range(value)


class PortFinding(BaseModel):
    port: int
    protocol: str
    service: str
    version: str


class HostFinding(BaseModel):
    address: str
    status: str
    ports: list[PortFinding]


class DiscoveryScanResult(BaseModel):
    target: str
    port_range: str
    status: ScanStatus
    hosts: list[HostFinding] = Field(default_factory=list)
    error: str | None = None


# ── Vulnerability Scanning (HU-003) ─────────────────────────────────


class VulnFinding(BaseModel):
    template_id: str
    name: str
    severity: VulnSeverity
    host: str
    matched_at: str
    tags: list[str] = Field(default_factory=list)
    description: str = ""
    references: list[str] = Field(default_factory=list)
    extracted_results: list[str] = Field(default_factory=list)
    scan_type: str = ""
    ip: str = ""
    timestamp: str = ""


class VulnScanRequest(BaseModel):
    target: str = Field(..., description="IP o FQDN del objetivo")
    templates: list[str] = Field(default_factory=list, description="Nombres de plantillas (sin ruta)")
    severities: list[str] = Field(default_factory=list, description="Filtro de severidades")
    tags: list[str] = Field(default_factory=list, description="Filtro de tags")

    @field_validator("target")
    @classmethod
    def check_target(cls, value: str) -> str:
        return validate_target(value)


class VulnScanResult(BaseModel):
    target: str
    status: ScanStatus
    findings: list[VulnFinding] = Field(default_factory=list)
    error: str | None = None
