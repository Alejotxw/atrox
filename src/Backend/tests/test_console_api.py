"""Tests del bus y API SSE de consola (HU-020)."""

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from atrox.console.bus import ScanLogBus, get_scan_log_bus, reset_scan_log_bus
from atrox.console.models import LogSeverity, ScanLogEvent
from atrox.main import app
from atrox.queue.models import Job, JobType
from atrox.queue.service import JobQueue
from atrox.scanner.nmap_wrapper import NmapWrapper
from atrox.scanner.nuclei_wrapper import NucleiWrapper
from tests.fixtures.nmap_samples import SAMPLE_NMAP_XML_UP
from tests.fixtures.nuclei_samples import SAMPLE_NUCLEI_JSONL_MULTI


@pytest.fixture(autouse=True)
def fresh_bus():
    reset_scan_log_bus()
    yield
    reset_scan_log_bus()


class TestScanLogBus:
    def test_publish_reaches_subscriber(self) -> None:
        async def _run() -> ScanLogEvent:
            bus = ScanLogBus(history_size=10)
            queue = await bus.subscribe()
            event = ScanLogEvent(
                module="NMAP",
                message="scan start",
                severity=LogSeverity.INFO,
            )
            await bus.publish(event)
            received = await queue.get()
            await bus.unsubscribe(queue)
            assert received is not None
            return received

        received = asyncio.run(_run())
        assert received.module == "NMAP"
        assert received.message == "scan start"

    def test_history_retained(self) -> None:
        async def _run() -> list[str]:
            bus = ScanLogBus(history_size=2)
            await bus.emit("A", "one")
            await bus.emit("B", "two")
            await bus.emit("C", "three")
            return [e.message for e in bus.history]

        assert asyncio.run(_run()) == ["two", "three"]

    def test_stream_yields_history_then_live(self) -> None:
        async def _run() -> list[str]:
            bus = ScanLogBus()
            await bus.emit("INFO", "hello console", severity=LogSeverity.INFO)
            messages: list[str] = []
            agen = bus.stream(include_history=True)
            first = await agen.__anext__()
            messages.append(first.message)
            await bus.emit("NMAP", "live line")
            second = await asyncio.wait_for(agen.__anext__(), timeout=1.0)
            messages.append(second.message)
            await agen.aclose()
            return messages

        assert asyncio.run(_run()) == ["hello console", "live line"]


class TestConsoleApi:
    def test_stream_route_registered(self) -> None:
        with TestClient(app) as client:
            schema = client.app.openapi()
            assert "/api/console/stream" in schema["paths"]
            assert "get" in schema["paths"]["/api/console/stream"]

    def test_sse_frame_shape_from_history(self) -> None:
        """Valida el payload que el endpoint serializa (sin dejar el stream abierto)."""
        from atrox.api.console import _sse_frame

        bus = reset_scan_log_bus()
        event = asyncio.run(
            bus.emit("INFO", "hello console", severity=LogSeverity.INFO)
        )
        frame = _sse_frame(event.model_dump(mode="json"))
        assert frame.startswith("data: ")
        payload = json.loads(frame.removeprefix("data: ").strip())
        assert payload["module"] == "INFO"
        assert payload["message"] == "hello console"
        assert payload["severity"] == "info"
        assert "timestamp" in payload
        assert get_scan_log_bus().history


class TestQueueEmitsLogs:
    def test_job_lifecycle_emits_logs(self) -> None:
        async def _run() -> list[str]:
            bus = reset_scan_log_bus()
            queue = JobQueue(max_concurrent=1, max_queue_size=5)

            async def scanner(job: Job) -> dict:
                return {"ok": True, "target": job.params.get("target")}

            await queue.start(scanner=scanner)
            job = await queue.submit(
                job_type=JobType.DISCOVERY,
                params={"target": "10.0.0.1"},
            )
            for _ in range(40):
                current = queue.get_job(job.id)
                if current and current.status.value in {"done", "failed"}:
                    break
                await asyncio.sleep(0.05)
            await queue.shutdown()
            return [e.module for e in bus.history]

        modules = asyncio.run(_run())
        assert "QUEUE" in modules
        assert "NMAP" in modules


class TestDispatchScanEmitsDetail:
    """_dispatch_scan (atrox/main.py) enriquece los eventos reales con detalle."""

    def test_discovery_emits_host_and_port_summary(self, monkeypatch) -> None:
        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, SAMPLE_NMAP_XML_UP, ""

        monkeypatch.setattr(
            "atrox.main.NmapWrapper",
            lambda **_kwargs: NmapWrapper(runner=mock_runner),
        )

        async def _run() -> list[ScanLogEvent]:
            from atrox.main import _dispatch_scan

            bus = reset_scan_log_bus()
            job = Job(
                job_type=JobType.DISCOVERY,
                params={"target": "192.168.1.10", "port_range": "22,80"},
            )
            await _dispatch_scan(job)
            return bus.history

        history = asyncio.run(_run())
        nmap_events = [e for e in history if e.module == "NMAP"]
        assert len(nmap_events) == 1
        assert nmap_events[0].severity == LogSeverity.INFO
        # SAMPLE_NMAP_XML_UP tiene 1 host up con 2 puertos abiertos (22, 80)
        assert "1 host" in nmap_events[0].message
        assert "2 puerto" in nmap_events[0].message

    def test_vulnscan_emits_critical_and_high_findings(self, monkeypatch) -> None:
        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, SAMPLE_NUCLEI_JSONL_MULTI, ""

        monkeypatch.setattr(
            "atrox.main.NucleiWrapper",
            lambda **_kwargs: NucleiWrapper(runner=mock_runner),
        )

        async def _run() -> list[ScanLogEvent]:
            from atrox.main import _dispatch_scan

            bus = reset_scan_log_bus()
            job = Job(
                job_type=JobType.VULNSCAN,
                params={"target": "192.168.1.10"},
            )
            await _dispatch_scan(job)
            return bus.history

        history = asyncio.run(_run())
        nuclei_events = [e for e in history if e.module == "NUCLEI"]
        # SAMPLE_NUCLEI_JSONL_MULTI trae 1 critical (Apache Path Traversal) y
        # 1 high (Confluence Auth Bypass); ambos deben emitirse.
        assert len(nuclei_events) == 2
        severities = {e.severity for e in nuclei_events}
        assert LogSeverity.CRITICAL in severities
        assert LogSeverity.WARNING in severities
        messages = " ".join(e.message for e in nuclei_events)
        assert "Apache HTTP Server Path Traversal" in messages
        assert "Confluence Auth Bypass" in messages

    def test_vulnscan_no_critical_or_high_emits_no_nuclei_detail(self, monkeypatch) -> None:
        low_only_jsonl = (
            '{"template-id":"low-check","info":{"name":"Low Severity Finding",'
            '"severity":"low","tags":[]},"host":"http://10.0.0.1",'
            '"matched-at":"http://10.0.0.1/low"}\n'
        )

        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, low_only_jsonl, ""

        monkeypatch.setattr(
            "atrox.main.NucleiWrapper",
            lambda **_kwargs: NucleiWrapper(runner=mock_runner),
        )

        async def _run() -> list[ScanLogEvent]:
            from atrox.main import _dispatch_scan

            bus = reset_scan_log_bus()
            job = Job(
                job_type=JobType.VULNSCAN,
                params={"target": "10.0.0.1"},
            )
            await _dispatch_scan(job)
            return bus.history

        history = asyncio.run(_run())
        assert [e for e in history if e.module == "NUCLEI"] == []


class TestDispatchScanFailsOnToolError:
    """_dispatch_scan (atrox/main.py) debe fallar el job cuando la herramienta
    nunca llegó a completar un escaneo real (binario ausente, timeout), en vez
    de devolver un resultado "exitoso" vacío indistinguible de "0 hallazgos".
    """

    def test_discovery_raises_when_nmap_not_found(self, monkeypatch) -> None:
        async def missing_binary_runner(_args: list[str]):
            raise FileNotFoundError("nmap no encontrado")

        monkeypatch.setattr(
            "atrox.main.NmapWrapper",
            lambda **_kwargs: NmapWrapper(runner=missing_binary_runner),
        )

        async def _run() -> None:
            from atrox.main import _dispatch_scan

            job = Job(
                job_type=JobType.DISCOVERY,
                params={"target": "192.168.1.10", "port_range": "22,80"},
            )
            await _dispatch_scan(job)

        with pytest.raises(RuntimeError, match="Nmap no encontrado"):
            asyncio.run(_run())

    def test_vulnscan_raises_when_nuclei_not_found(self, monkeypatch) -> None:
        async def missing_binary_runner(_args: list[str]):
            raise FileNotFoundError("nuclei no encontrado")

        monkeypatch.setattr(
            "atrox.main.NucleiWrapper",
            lambda **_kwargs: NucleiWrapper(runner=missing_binary_runner),
        )

        async def _run() -> None:
            from atrox.main import _dispatch_scan

            job = Job(job_type=JobType.VULNSCAN, params={"target": "192.168.1.10"})
            await _dispatch_scan(job)

        with pytest.raises(RuntimeError, match="Nuclei no encontrado"):
            asyncio.run(_run())

    def test_job_queue_marks_job_failed_with_real_error_when_tool_missing(
        self, monkeypatch
    ) -> None:
        """Verifica el flujo completo: JobQueue debe marcar FAILED (no DONE)
        cuando el dispatcher lanza porque la herramienta no corrió."""

        async def missing_binary_runner(_args: list[str]):
            raise FileNotFoundError("nuclei no encontrado")

        monkeypatch.setattr(
            "atrox.main.NucleiWrapper",
            lambda **_kwargs: NucleiWrapper(runner=missing_binary_runner),
        )

        async def _run() -> Job:
            from atrox.main import _dispatch_scan

            reset_scan_log_bus()
            queue = JobQueue(max_concurrent=1, max_queue_size=5)
            await queue.start(scanner=_dispatch_scan)
            job = await queue.submit(
                job_type=JobType.VULNSCAN,
                params={"target": "192.168.1.10"},
            )
            for _ in range(40):
                current = queue.get_job(job.id)
                if current and current.status.value in {"done", "failed"}:
                    break
                await asyncio.sleep(0.05)
            await queue.shutdown()
            return queue.get_job(job.id)

        job = asyncio.run(_run())
        assert job.status.value == "failed"
        assert job.error is not None
        assert "Nuclei no encontrado" in job.error


class TestDispatchScanEmitsRealCommand:
    """_dispatch_scan debe mostrar el comando real ejecutado (HU-020 UX:
    el usuario quiere ver "$ nmap ..." / "$ nuclei ..." en la consola, no
    solo un resumen abstracto del resultado)."""

    def test_discovery_emits_real_nmap_command_before_summary(self, monkeypatch) -> None:
        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, SAMPLE_NMAP_XML_UP, ""

        monkeypatch.setattr(
            "atrox.main.NmapWrapper",
            lambda **kwargs: NmapWrapper(
                runner=mock_runner, on_command=kwargs.get("on_command")
            ),
        )

        async def _run() -> list[ScanLogEvent]:
            from atrox.main import _dispatch_scan

            bus = reset_scan_log_bus()
            job = Job(
                job_type=JobType.DISCOVERY,
                params={"target": "192.168.1.10", "port_range": "22,80"},
            )
            await _dispatch_scan(job)
            return bus.history

        history = asyncio.run(_run())
        nmap_events = [e for e in history if e.module == "NMAP"]
        assert len(nmap_events) == 2
        assert nmap_events[0].message.startswith("$ nmap ")
        assert "192.168.1.10" in nmap_events[0].message
        # El resumen de hosts/puertos debe llegar DESPUES del comando
        assert "host" in nmap_events[1].message

    def test_vulnscan_emits_real_nuclei_command_before_findings(self, monkeypatch) -> None:
        async def mock_runner(_args: list[str]) -> tuple[int, str, str]:
            return 0, SAMPLE_NUCLEI_JSONL_MULTI, ""

        monkeypatch.setattr(
            "atrox.main.NucleiWrapper",
            lambda **kwargs: NucleiWrapper(
                runner=mock_runner, on_command=kwargs.get("on_command")
            ),
        )

        async def _run() -> list[ScanLogEvent]:
            from atrox.main import _dispatch_scan

            bus = reset_scan_log_bus()
            job = Job(job_type=JobType.VULNSCAN, params={"target": "192.168.1.10"})
            await _dispatch_scan(job)
            return bus.history

        history = asyncio.run(_run())
        nuclei_events = [e for e in history if e.module == "NUCLEI"]
        assert len(nuclei_events) == 3
        assert nuclei_events[0].message.startswith("$ nuclei ")
        assert "192.168.1.10" in nuclei_events[0].message
