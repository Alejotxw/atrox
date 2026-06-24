import asyncio
import logging
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


class NmapWrapper:
    """Wrapper asíncrono de Nmap para descubrimiento de activos."""

    def __init__(
        self,
        nmap_path: str = "nmap",
        timeout_seconds: int = 300,
        runner: NmapRunner | None = None,
    ) -> None:
        self.nmap_path = nmap_path
        self.timeout_seconds = timeout_seconds
        self._runner = runner

    async def scan(self, target: str, port_range: str) -> DiscoveryScanResult:
        args = [
            "-sV",
            "-p",
            port_range,
            "-oX",
            "-",
            "--host-timeout",
            f"{self.timeout_seconds}s",
            target,
        ]

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
                error=str(exc),
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

        process = await asyncio.create_subprocess_exec(
            self.nmap_path,
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

    def _parse_xml(self, xml_output: str) -> list[HostFinding]:
        root = ET.fromstring(xml_output)
        hosts: list[HostFinding] = []

        for host_elem in root.findall("host"):
            status_elem = host_elem.find("status")
            host_status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

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
                        version = self._build_version(service_elem)

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

    @staticmethod
    def _build_version(service_elem: ET.Element) -> str:
        product = service_elem.get("product", "")
        version = service_elem.get("version", "")
        extrainfo = service_elem.get("extrainfo", "")

        parts = [part for part in (product, version, extrainfo) if part]
        return " ".join(parts)
