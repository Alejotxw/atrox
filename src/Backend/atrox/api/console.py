"""API SSE de consola de logs de escaneo (HU-020)."""

from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator

from atrox.console.bus import ScanLogBus, get_scan_log_bus
from atrox.console.models import LogSeverity
from atrox.console.simulator import run_simulated_scan
from atrox.scanner.validators import validate_target

router = APIRouter(prefix="/api/console", tags=["console"])


class SimulateRequest(BaseModel):
    """Payload para demo simulada de logs en vivo."""

    target: str = Field(default="lab.local", min_length=1, max_length=253)

    @field_validator("target")
    @classmethod
    def check_target(cls, value: str) -> str:
        return validate_target(value)


class SimulateResponse(BaseModel):
    status: str
    target: str


def get_console_bus(request: Request) -> ScanLogBus:
    bus = getattr(request.app.state, "scan_log_bus", None)
    return bus if bus is not None else get_scan_log_bus()


def _sse_frame(payload: dict) -> str:
    return f"data: {json.dumps(payload, default=str)}\n\n"


async def _event_stream(bus: ScanLogBus) -> AsyncIterator[str]:
    """Genera frames SSE; envía keepalive cada ~15s si no hay eventos."""
    queue = await bus.subscribe()
    try:
        for event in bus.history:
            yield _sse_frame(event.model_dump(mode="json"))

        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=15.0)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
                continue
            if item is None:
                break
            yield _sse_frame(item.model_dump(mode="json"))
    finally:
        await bus.unsubscribe(queue)


@router.get("/stream")
async def stream_console_logs(request: Request) -> StreamingResponse:
    """Stream SSE de logs: timestamp, módulo y severidad por línea."""
    bus = get_console_bus(request)

    async def generate() -> AsyncIterator[str]:
        async for chunk in _event_stream(bus):
            if await request.is_disconnected():
                break
            yield chunk

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/simulate", response_model=SimulateResponse, status_code=202)
async def simulate_console_scan(
    body: SimulateRequest,
    request: Request,
) -> SimulateResponse:
    """Arranca una demo simulada que emite logs por el stream SSE (DoD HU-020)."""
    bus = get_console_bus(request)
    await bus.emit(
        "INFO",
        f"Simulated scan requested for {body.target}",
        severity=LogSeverity.INFO,
    )
    asyncio.create_task(run_simulated_scan(bus, body.target))
    return SimulateResponse(status="started", target=body.target)
