import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path

from atrox.scanner.models import (
    ScanStatus,
    VulnFinding,
    VulnScanResult,
    VulnSeverity,
)

logger = logging.getLogger(__name__)

NucleiRunner = Callable[[list[str]], Awaitable[tuple[int, str, str]]]

REQUIRED_JSONL_FIELDS = ("template-id", "host", "matched-at")
REQUIRED_INFO_FIELDS = ("name", "severity")


def parse_nuclei_jsonl(output: str) -> list[VulnFinding]:
    """Parsea la salida JSONL de Nuclei y retorna lista de hallazgos.

    Funcion a nivel de modulo (picklable) para uso con ProcessPoolExecutor.
    """
    findings: list[VulnFinding] = []

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            logger.warning("Linea JSONL malformada omitida: %s", stripped[:100])
            continue

        if not isinstance(data, dict):
            logger.warning("Linea JSONL no es un objeto: %s", stripped[:100])
            continue

        info = data.get("info", {})
        if not isinstance(info, dict):
            logger.warning("Campo 'info' invalido, linea omitida")
            continue

        template_id = data.get("template-id", "")
        name = info.get("name", "")
        raw_severity = info.get("severity", "")

        if not template_id or not name or not raw_severity:
            logger.warning(
                "Campos requeridos faltantes (template-id, info.name, info.severity), linea omitida"
            )
            continue

        host = data.get("host", "")
        matched_at = data.get("matched-at", "")

        if not host or not matched_at:
            logger.warning(
                "Campos requeridos faltantes (host, matched-at), linea omitida"
            )
            continue

        try:
            severity = VulnSeverity(raw_severity.lower())
        except ValueError:
            severity = VulnSeverity.UNKNOWN

        findings.append(
            VulnFinding(
                template_id=template_id,
                name=name,
                severity=severity,
                host=host,
                matched_at=matched_at,
                tags=info.get("tags", []),
                description=info.get("description", ""),
                references=info.get("reference", []),
                extracted_results=data.get("extracted-results", []),
                scan_type=data.get("type", ""),
                ip=data.get("ip", ""),
                timestamp=data.get("timestamp", ""),
            )
        )

    return findings


class NucleiWrapper:
    """Wrapper asincrono de Nuclei para escaneo de vulnerabilidades."""

    def __init__(
        self,
        nuclei_path: str = "nuclei",
        timeout_seconds: int = 300,
        sandbox_templates: str | None = None,
        runner: NucleiRunner | None = None,
    ) -> None:
        self.nuclei_path = nuclei_path
        self.timeout_seconds = timeout_seconds
        self.sandbox_templates = sandbox_templates
        self._runner = runner

    async def scan(
        self,
        target: str,
        templates: list[str] | None = None,
        severities: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> VulnScanResult:
        args = ["-u", target, "-jsonl", "-silent", "-nc", "-or"]

        if templates and self.sandbox_templates:
            try:
                resolved = self._resolve_templates(templates)
            except ValueError as exc:
                return VulnScanResult(
                    target=target,
                    status=ScanStatus.ERROR,
                    error=str(exc),
                )
            for path in resolved:
                args.extend(["-t", path])

        if severities:
            args.extend(["-severity", ",".join(severities)])

        if tags:
            args.extend(["-tags", ",".join(tags)])

        try:
            return_code, stdout, stderr = await self._execute(args)
        except FileNotFoundError:
            logger.exception("Nuclei no encontrado en el sistema")
            return VulnScanResult(
                target=target,
                status=ScanStatus.ERROR,
                error="Nuclei no encontrado. Instale Nuclei o configure ATROX_NUCLEI_PATH.",
            )
        except (asyncio.TimeoutError, TimeoutError):
            logger.warning("Timeout escaneando %s", target)
            return VulnScanResult(
                target=target,
                status=ScanStatus.TIMEOUT,
                error=f"El escaneo excedio el tiempo limite de {self.timeout_seconds}s",
            )
        except Exception as exc:
            logger.exception("Error inesperado escaneando %s", target)
            return VulnScanResult(
                target=target,
                status=ScanStatus.ERROR,
                error=str(exc),
            )

        if not stdout.strip() and return_code != 0:
            message = stderr.strip() or f"Nuclei finalizo con codigo {return_code}"
            return VulnScanResult(
                target=target,
                status=ScanStatus.ERROR,
                error=message,
            )

        findings = self._parse_jsonl(stdout)

        return VulnScanResult(
            target=target,
            status=ScanStatus.COMPLETED,
            findings=findings,
        )

    async def _execute(self, args: list[str]) -> tuple[int, str, str]:
        if self._runner is not None:
            return await asyncio.wait_for(
                self._runner(args),
                timeout=self.timeout_seconds,
            )

        process = await asyncio.create_subprocess_exec(
            self.nuclei_path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise

        return (
            process.returncode or 0,
            stdout_bytes.decode(errors="replace"),
            stderr_bytes.decode(errors="replace"),
        )

    def _parse_jsonl(self, output: str) -> list[VulnFinding]:
        """Delega al parse a nivel de modulo para compatibilidad."""
        return parse_nuclei_jsonl(output)

    def _resolve_templates(self, template_names: list[str]) -> list[str]:
        if not self.sandbox_templates:
            raise ValueError("Sandbox de plantillas no configurado")

        base = Path(self.sandbox_templates).resolve()
        resolved: list[str] = []

        for name in template_names:
            full_path = (base / name).resolve()
            if not full_path.is_relative_to(base):
                raise ValueError(
                    f"Plantilla no permitida fuera del sandbox: {name}"
                )
            resolved.append(str(full_path))

        return resolved
