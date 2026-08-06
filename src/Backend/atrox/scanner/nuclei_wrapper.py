import asyncio
import json
import logging
import subprocess
import uuid
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


OnCommand = Callable[[list[str]], Awaitable[None]]


class NucleiWrapper:
    """Wrapper asincrono de Nuclei para escaneo de vulnerabilidades."""

    def __init__(
        self,
        nuclei_path: str = "nuclei",
        timeout_seconds: int = 300,
        sandbox_templates: str | None = None,
        runner: NucleiRunner | None = None,
        on_command: OnCommand | None = None,
        docker_image: str | None = None,
        docker_templates_volume: str | None = "atrox-nuclei-templates",
    ) -> None:
        self.nuclei_path = nuclei_path
        self.timeout_seconds = timeout_seconds
        self.sandbox_templates = sandbox_templates
        self._runner = runner
        self._on_command = on_command
        self._docker_image = docker_image
        self._docker_templates_volume = docker_templates_volume
        self._docker_container_name: str | None = None

    def _base_command(self) -> list[str]:
        """Comando base antes de los flags de Nuclei.

        Si `docker_image` está configurado, corre Nuclei dentro de un
        contenedor (`docker run --rm -i --name <id> <imagen>`) en vez del
        binario nativo — evita por completo el filtrado de antivirus de
        Windows sobre el ejecutable, a costa de requerir Docker Desktop
        corriendo. El volumen con nombre persiste `nuclei-templates` entre
        ejecuciones — sin esto, cada contenedor `--rm` re-descarga el
        catálogo completo de plantillas en cada escaneo (varios minutos).
        El nombre del contenedor se fija una sola vez por escaneo para poder
        detenerlo explícitamente si se agota el timeout (ver `_run_subprocess_blocking`).
        """
        if not self._docker_image:
            return [self.nuclei_path]

        if self._docker_container_name is None:
            self._docker_container_name = f"atrox-nuclei-{uuid.uuid4().hex[:12]}"

        command = ["docker", "run", "--rm", "-i", "--name", self._docker_container_name]
        if self._docker_templates_volume:
            command.extend(["-v", f"{self._docker_templates_volume}:/root/nuclei-templates"])
        command.append(self._docker_image)
        return command

    async def scan(
        self,
        target: str,
        templates: list[str] | None = None,
        severities: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> VulnScanResult:
        self._docker_container_name = None
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

        if self._on_command is not None:
            await self._on_command([*self._base_command(), *args])

        try:
            return_code, stdout, stderr = await self._execute(args)
        except FileNotFoundError:
            logger.exception("Nuclei no encontrado en el sistema")
            error = (
                "Docker no encontrado. Instale Docker Desktop o desactive ATROX_NUCLEI_DOCKER_IMAGE."
                if self._docker_image
                else "Nuclei no encontrado. Instale Nuclei o configure ATROX_NUCLEI_PATH."
            )
            return VulnScanResult(target=target, status=ScanStatus.ERROR, error=error)
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
                error=str(exc) or f"{type(exc).__name__} sin mensaje (ver logs del servidor)",
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

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._run_subprocess_blocking, args)

    def _run_subprocess_blocking(self, args: list[str]) -> tuple[int, str, str]:
        """Ejecuta Nuclei de forma síncrona/bloqueante en un hilo del executor.

        `asyncio.create_subprocess_exec` no funciona bajo `SelectorEventLoop`
        (el loop que uvicorn usa en Windows cuando corre con `--reload` o
        `--workers > 1`, ver `Config.use_subprocess` en uvicorn) — lanza
        `NotImplementedError`. `subprocess.Popen` sí funciona en cualquier
        tipo de event loop porque no depende de su soporte de subprocesos;
        al correr en un hilo aparte, no bloquea el loop de asyncio.
        """
        process = subprocess.Popen(
            [*self._base_command(), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=self.timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            if self._docker_image and self._docker_container_name:
                self._kill_docker_container(self._docker_container_name)
            raise TimeoutError(
                f"El escaneo excedio el tiempo limite de {self.timeout_seconds}s"
            ) from None

        return (
            process.returncode or 0,
            stdout_bytes.decode(errors="replace"),
            stderr_bytes.decode(errors="replace"),
        )

    def _kill_docker_container(self, name: str) -> None:
        """Detiene el contenedor Docker explícitamente al agotar el timeout.

        Matar el proceso local `docker run` (`Popen.kill`) en Windows no le
        avisa al daemon de Docker que detenga el contenedor — queda huérfano
        corriendo indefinidamente y sigue consumiendo CPU/red. Hay que
        detenerlo por su nombre explícitamente.
        """
        try:
            subprocess.run(
                ["docker", "kill", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except Exception:
            logger.exception("No se pudo detener el contenedor Docker huérfano %s", name)

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
