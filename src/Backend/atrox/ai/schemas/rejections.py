"""Log de rechazos de respuestas IA para depuración (HU-017).

Todo rechazo de una respuesta del LLM (JSON inválido o esquema no cumplido)
se registra con timestamp, tipo de salida, error y respuesta cruda (truncada).
El logger mantiene un buffer en memoria siempre disponible para consulta en
tiempo de ejecución; si se configura `log_path`, además persiste en un archivo
JSONL append-only (mismo patrón que el log de auditoría de HU-008).
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

RAW_MAX_LEN = 4000


class RejectionRecord(BaseModel):
    """Registro de un rechazo: tipo de salida, error y respuesta cruda."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    kind: str
    model_name: str
    error: str
    detail: str
    raw: str
    attempt: int


class RejectionLogStore:
    """Almacén append-only (JSONL) de rechazos para depuración posterior."""

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path
        self._lock = asyncio.Lock()
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def log_path(self) -> Path:
        return self._log_path

    async def append(self, record: RejectionRecord) -> None:
        line = json.dumps(record.model_dump(mode="json"), ensure_ascii=False)
        async with self._lock:
            with self._log_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    async def read_all(self) -> list[dict[str, Any]]:
        if not self._log_path.exists():
            return []

        async with self._lock:
            content = self._log_path.read_text(encoding="utf-8")

        entries: list[dict[str, Any]] = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
        return entries


class RejectionLogger:
    """Registra rechazos en memoria (siempre) y en un store JSONL (opcional).

    Cada rechazo también se emite por el módulo `logging` a nivel ERROR para
    depuración inmediata en consola.
    """

    def __init__(self, store: RejectionLogStore | None = None) -> None:
        self._store = store
        self._records: list[RejectionRecord] = []

    async def record(
        self,
        *,
        kind: str,
        error: str,
        detail: str,
        raw: str,
        attempt: int,
        model_name: str = "llm",
    ) -> RejectionRecord:
        record = RejectionRecord(
            kind=kind,
            model_name=model_name,
            error=error,
            detail=detail,
            raw=raw[:RAW_MAX_LEN],
            attempt=attempt,
        )
        self._records.append(record)
        logger.error(
            "Respuesta IA rechazada [%s] intento=%s %s: %s", kind, attempt, error, detail
        )
        if self._store is not None:
            await self._store.append(record)
        return record

    async def read_all(self) -> list[RejectionRecord]:
        return list(self._records)


def build_rejection_logger(log_path: str | Path | None) -> RejectionLogger:
    """Construye el logger: con persistencia JSONL si `log_path` está configurado."""
    if log_path:
        return RejectionLogger(store=RejectionLogStore(Path(log_path)))
    return RejectionLogger()
