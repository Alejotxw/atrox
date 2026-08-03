"""Almacén JSONL append/update para entidades cifradas en reposo (HU-007)."""

import asyncio
import json
from pathlib import Path
from typing import Any
from uuid import UUID


class JsonEntityStore:
    """Persistencia simple en archivo JSONL (una entidad por línea)."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    async def upsert(self, entity_id: UUID | str, data: dict[str, Any]) -> None:
        async with self._lock:
            records = self._read_unlocked()
            key = str(entity_id)
            records[key] = data
            self._write_unlocked(records)

    async def get(self, entity_id: UUID | str) -> dict[str, Any] | None:
        async with self._lock:
            return self._read_unlocked().get(str(entity_id))

    async def list_all(self) -> list[dict[str, Any]]:
        async with self._lock:
            return list(self._read_unlocked().values())

    async def delete(self, entity_id: UUID | str) -> bool:
        async with self._lock:
            records = self._read_unlocked()
            key = str(entity_id)
            if key not in records:
                return False
            del records[key]
            self._write_unlocked(records)
            return True

    def read_raw_lines(self) -> list[str]:
        """Lectura cruda del archivo (para verificar cifrado en reposo)."""
        if not self._path.exists():
            return []
        return [
            line
            for line in self._path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def _read_unlocked(self) -> dict[str, dict[str, Any]]:
        if not self._path.exists():
            return {}
        records: dict[str, dict[str, Any]] = {}
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            records[str(item["id"])] = item
        return records

    def _write_unlocked(self, records: dict[str, dict[str, Any]]) -> None:
        with self._path.open("w", encoding="utf-8") as handle:
            for item in records.values():
                handle.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
