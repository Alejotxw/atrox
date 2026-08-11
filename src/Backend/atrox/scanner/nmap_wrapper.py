import asyncio
import logging
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable

from atrox.scanner.models import (
    DiscoveryScanResult,
    HostFinding,
    PortFinding,
    ScanStatus,
)

logger = logging.getLogger(__name__)

NmapRunner = Callable[[list[str]], Awaitable[tuple[int, str, str]]]


def _build_version(service_elem: ET.Element) -> str:
    """Construye cadena de version a partir del elemento service de Nmap."""
    product = service_elem.get("product", "")
    version = service_elem.get("version", "")
    extrainfo = service_elem.get("extrainfo", "")

    parts = [part for part in (product, version, extrainfo) if part]
    return " ".join(parts)


def parse_nmap_xml(xml_output: str) -> list[HostFinding]:
    """Parsea la salida XML de Nmap y retorna lista de hosts encontrados.

    Funcion a nivel de modulo (picklable) para uso con ProcessPoolExecutor.
    """
    root = ET.fromstring(xml_output)
    hosts: list[HostFinding] = []

    for host_elem in root.findall("host"):
        status_elem = host_elem.find("status")
        host_status = (
            status_elem.get("state", "unknown") if status_elem is not None else "unknown"
        )

        address = ""
        for addr_elem in host_elem.findall("address"):
            if addr_elem.get("addrtype") in {"ipv4", "ipv6"}:
                address = addr_elem.get("addr", "")
                break

        ports: list[PortFinding] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                service_elem = port_elem.find("service")
                service_name = ""
                version = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    version = _build_version(service_elem)

                ports.append(
                    PortFinding(
                        port=int(port_elem.get("portid", "0")),
                        protocol=port_elem.get("protocol", "tcp"),
                        service=service_name,
                        version=version,
                    )
                )

        hosts.append(
            HostFinding(
                address=address or "unknown",
                status=host_status,
                ports=ports,
            )
        )

    return hosts


OnCommand = Callable[[list[str]], Awaitable[None]]


class NmapWrapper:
    """Wrapper asíncrono de Nmap para descubrimiento de activos."""

    def __init__(
        self,
        nmap_path: str = "nmap",
        timeout_seconds: int = 300,
        runner: NmapRunner | None = None,
        on_command: OnCommand | None = None,
    ) -> None:
        self.nmap_path = nmap_path
        self.timeout_seconds = timeout_seconds
        self._runner = runner
        self._on_command = on_command

    async def scan(self, target: str, port_range: str) -> DiscoveryScanResult:
        # Flags rápidos para demos (<2 min): timing agresivo, menos reintentos
        # y versionado ligero (el -sV completo sobre 1-1024 es lo que demora minutos).
        args = [
            "-sV",
            "--version-intensity",
            "2",
            "-T4",
            "--max-retries",
            "1",
            "-p",
            port_range,
            "-oX",
            "-",
            "--host-timeout",
            f"{self.timeout_seconds}s",
            target,
        ]

        if self._on_command is not None:
            await self._on_command([self.nmap_path, *args])

        try:
            return_code, stdout, stderr = await self._execute(args)
        except FileNotFoundError:
            logger.exception("Nmap no encontrado en el sistema")
            return DiscoveryScanResult(
                target=target,
                port_range=port_range,
                status=ScanStatus.ERROR,
                error=f"Nmap no encontrado. Instale Nmap o configure ATROX_NMAP_PATH.",
            )
        except asyncio.TimeoutError:
            logger.warning("Timeout escaneando %s", target)
            return DiscoveryScanResult(
                target=target,
                port_range=port_range,
                status=ScanStatus.TIMEOUT,
                error=f"El escaneo excedió el tiempo límite de {self.timeout_seconds}s",
            )
        except Exception as exc:
            logger.exception("Error inesperado escaneando %s", target)
            return DiscoveryScanResult(
                target=target,
                port_range=port_range,
                status=ScanStatus.ERROR,
                error=str(exc) or f"{type(exc).__name__} sin mensaje (ver logs del servidor)",
            )

        if not stdout.strip():
            message = stderr.strip() or f"Nmap finalizó con código {return_code}"
            return DiscoveryScanResult(
                target=target,
                port_range=port_range,
                status=ScanStatus.ERROR,
                error=message,
            )

        hosts = self._parse_xml(stdout)

        if not hosts or all(host.status == "down" for host in hosts):
            return DiscoveryScanResult(
                target=target,
                port_range=port_range,
                status=ScanStatus.UNREACHABLE,
                hosts=hosts,
                error="El objetivo no respondió al escaneo",
            )

        return DiscoveryScanResult(
            target=target,
            port_range=port_range,
            status=ScanStatus.COMPLETED,
            hosts=hosts,
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
        """Ejecuta Nmap de forma síncrona/bloqueante en un hilo del executor.

        `asyncio.create_subprocess_exec` no funciona bajo `SelectorEventLoop`
        (el loop que uvicorn usa en Windows cuando corre con `--reload` o
        `--workers > 1`, ver `Config.use_subprocess` en uvicorn) — lanza
        `NotImplementedError`. `subprocess.Popen` sí funciona en cualquier
        tipo de event loop porque no depende de su soporte de subprocesos;
        al correr en un hilo aparte, no bloquea el loop de asyncio.
        """
        process = subprocess.Popen(
            [self.nmap_path, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=self.timeout_seconds)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise TimeoutError(
                f"El escaneo excedió el tiempo límite de {self.timeout_seconds}s"
            ) from None

        return (
            process.returncode or 0,
            stdout_bytes.decode(errors="replace"),
            stderr_bytes.decode(errors="replace"),
        )

    def _parse_xml(self, xml_output: str) -> list[HostFinding]:
        """Delega al parse a nivel de modulo para compatibilidad."""
        return parse_nmap_xml(xml_output)
