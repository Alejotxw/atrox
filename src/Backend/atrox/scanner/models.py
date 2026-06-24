from enum import Enum

from pydantic import BaseModel, Field, field_validator

from atrox.scanner.validators import validate_port_range, validate_target


class ScanStatus(str, Enum):
    COMPLETED = "completed"
    UNREACHABLE = "unreachable"
    TIMEOUT = "timeout"
    ERROR = "error"


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
