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
    def test_simulate_returns_202(self) -> None:
        with TestClient(app) as client:
            response = client.post(
                "/api/console/simulate",
                json={"target": "192.168.1.10"},
            )
            assert response.status_code == 202
            body = response.json()
            assert body["status"] == "started"
            assert body["target"] == "192.168.1.10"

    def test_stream_route_registered(self) -> None:
        with TestClient(app) as client:
            schema = client.app.openapi()
            assert "/api/console/stream" in schema["paths"]
            assert "/api/console/simulate" in schema["paths"]
            assert "get" in schema["paths"]["/api/console/stream"]
            assert "post" in schema["paths"]["/api/console/simulate"]

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
