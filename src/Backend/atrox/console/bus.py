"""Bus pub/sub en memoria para stream de logs de escaneo (HU-020)."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterator
from typing import Deque

from atrox.console.models import LogSeverity, ScanLogEvent

_bus: ScanLogBus | None = None


class ScanLogBus:
    """Publica eventos a suscriptores SSE y conserva un ring buffer reciente."""

    def __init__(self, history_size: int = 200) -> None:
        self._history: Deque[ScanLogEvent] = deque(maxlen=history_size)
        self._subscribers: set[asyncio.Queue[ScanLogEvent | None]] = set()
        self._lock = asyncio.Lock()

    @property
    def history(self) -> list[ScanLogEvent]:
        return list(self._history)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    async def publish(self, event: ScanLogEvent) -> ScanLogEvent:
        """Publica un evento a todos los suscriptores y al historial."""
        async with self._lock:
            self._history.append(event)
            dead: list[asyncio.Queue[ScanLogEvent | None]] = []
            for queue in self._subscribers:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    dead.append(queue)
            for queue in dead:
                self._subscribers.discard(queue)
        return event

    async def emit(
        self,
        module: str,
        message: str,
        *,
        severity: LogSeverity = LogSeverity.INFO,
        job_id=None,
    ) -> ScanLogEvent:
        """Atajo para crear y publicar un ScanLogEvent."""
        event = ScanLogEvent(
            module=module,
            message=message,
            severity=severity,
            job_id=job_id,
        )
        return await self.publish(event)

    async def subscribe(self) -> asyncio.Queue[ScanLogEvent | None]:
        """Registra un suscriptor; None en la cola señala cierre."""
        queue: asyncio.Queue[ScanLogEvent | None] = asyncio.Queue(maxsize=256)
        async with self._lock:
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue[ScanLogEvent | None]) -> None:
        async with self._lock:
            self._subscribers.discard(queue)

    async def stream(self, *, include_history: bool = True) -> AsyncIterator[ScanLogEvent]:
        """Itera eventos; primero historial (opcional) y luego live hasta cancelación."""
        queue = await self.subscribe()
        try:
            if include_history:
                for event in self.history:
                    yield event
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield item
        finally:
            await self.unsubscribe(queue)


def get_scan_log_bus() -> ScanLogBus:
    """Singleton del bus de logs (compartido entre API y cola)."""
    global _bus
    if _bus is None:
        _bus = ScanLogBus()
    return _bus


def reset_scan_log_bus() -> ScanLogBus:
    """Recrea el bus (útil en tests)."""
    global _bus
    _bus = ScanLogBus()
    return _bus
