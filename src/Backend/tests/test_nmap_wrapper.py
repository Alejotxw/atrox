import asyncio
import sys

import pytest

from atrox.scanner.models import ScanStatus
from atrox.scanner.nmap_wrapper import NmapWrapper
from atrox.scanner.validators import validate_port_range, validate_target
from tests.fixtures.nmap_samples import SAMPLE_NMAP_XML_DOWN, SAMPLE_NMAP_XML_UP


def test_validate_target_accepts_ipv4() -> None:
    assert validate_target("192.168.1.1") == "192.168.1.1"


def test_validate_target_accepts_fqdn() -> None:
    assert validate_target("scanme.nmap.org") == "scanme.nmap.org"


def test_validate_target_rejects_invalid() -> None:
    with pytest.raises(ValueError, match="Objetivo inválido"):
        validate_target("not a valid target!!")


def test_validate_port_range_accepts_list_and_range() -> None:
    assert validate_port_range("22,80,443") == "22,80,443"
    assert validate_port_range("1-1024") == "1-1024"


def test_validate_port_range_rejects_invalid() -> None:
    with pytest.raises(ValueError):
        validate_port_range("70000")


def test_scan_parses_open_ports_from_mocked_nmap() -> None:
    async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
        return 0, SAMPLE_NMAP_XML_UP, ""

    wrapper = NmapWrapper(runner=mock_runner)

    result = asyncio.run(wrapper.scan("192.168.1.10", "22,80,443"))

    assert result.status == ScanStatus.COMPLETED
    assert len(result.hosts) == 1
    assert result.hosts[0].address == "192.168.1.10"
    assert len(result.hosts[0].ports) == 2

    ssh_port = result.hosts[0].ports[0]
    assert ssh_port.port == 22
    assert ssh_port.protocol == "tcp"
    assert ssh_port.service == "ssh"
    assert ssh_port.version == "OpenSSH 8.9p1 Ubuntu"

    http_port = result.hosts[0].ports[1]
    assert http_port.port == 80
    assert http_port.service == "http"
    assert http_port.version == "Apache httpd 2.4.52"


def test_scan_invokes_on_command_with_real_args_before_running() -> None:
    async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
        return 0, SAMPLE_NMAP_XML_UP, ""

    captured: list[list[str]] = []

    async def on_command(args: list[str]) -> None:
        captured.append(args)

    wrapper = NmapWrapper(
        nmap_path="nmap",
        runner=mock_runner,
        on_command=on_command,
    )

    asyncio.run(wrapper.scan("192.168.1.10", "22,80,443"))

    assert len(captured) == 1
    command = captured[0]
    assert command[0] == "nmap"
    assert "-p" in command
    assert "22,80,443" in command
    assert "192.168.1.10" in command


def test_scan_handles_unreachable_target_without_crash() -> None:
    async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
        return 0, SAMPLE_NMAP_XML_DOWN, ""

    wrapper = NmapWrapper(runner=mock_runner)

    result = asyncio.run(wrapper.scan("10.255.255.1", "22"))

    assert result.status == ScanStatus.UNREACHABLE
    assert result.error is not None
    assert result.hosts[0].status == "down"
    assert result.hosts[0].ports == []


def test_scan_handles_timeout_without_crash() -> None:
    async def slow_runner(_args: list[str]) -> tuple[int, str, str]:
        await asyncio.sleep(2)
        return 0, SAMPLE_NMAP_XML_UP, ""

    wrapper = NmapWrapper(timeout_seconds=1, runner=slow_runner)

    result = asyncio.run(wrapper.scan("192.168.1.10", "80"))

    assert result.status == ScanStatus.TIMEOUT
    assert "tiempo límite" in (result.error or "")


def test_scan_handles_missing_nmap_binary() -> None:
    async def missing_runner(_args: list[str]) -> tuple[int, str, str]:
        raise FileNotFoundError("nmap not found")

    wrapper = NmapWrapper(runner=missing_runner)

    result = asyncio.run(wrapper.scan("127.0.0.1", "80"))

    assert result.status == ScanStatus.ERROR
    assert result.error is not None
    assert "Nmap no encontrado" in result.error


def test_scan_handles_empty_output() -> None:
    async def empty_runner(_args: list[str]) -> tuple[int, str, str]:
        return 1, "", "Failed to resolve"

    wrapper = NmapWrapper(runner=empty_runner)

    result = asyncio.run(wrapper.scan("invalid.internal", "80"))

    assert result.status == ScanStatus.ERROR
    assert result.error is not None


class TestRealSubprocessPath:
    """Sin `runner` inyectado: usa subprocess.Popen bloqueante en un hilo del
    executor (no asyncio.create_subprocess_exec) — funciona incluso bajo
    SelectorEventLoop, el loop que uvicorn usa en Windows con --reload."""

    def test_execute_runs_real_subprocess_and_captures_output(self) -> None:
        wrapper = NmapWrapper(nmap_path=sys.executable, timeout_seconds=5)

        return_code, stdout, stderr = asyncio.run(
            wrapper._execute(["-c", "import sys; print('ok'); sys.exit(0)"])
        )

        assert return_code == 0
        assert "ok" in stdout

    def test_execute_raises_file_not_found_for_missing_binary(self) -> None:
        wrapper = NmapWrapper(
            nmap_path="definitely-not-a-real-binary-xyz123", timeout_seconds=5
        )

        with pytest.raises(FileNotFoundError):
            asyncio.run(wrapper._execute(["--version"]))

    def test_execute_raises_timeout_error_when_process_hangs(self) -> None:
        wrapper = NmapWrapper(nmap_path=sys.executable, timeout_seconds=1)

        with pytest.raises(asyncio.TimeoutError):
            asyncio.run(
                wrapper._execute(["-c", "import time; time.sleep(5)"])
            )
