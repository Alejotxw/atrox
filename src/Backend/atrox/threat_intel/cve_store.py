"""Almacén del catálogo de CVEs y del estado de última sincronización (HU-005).

Mismo patrón de persistencia que `atrox/security/audit_service.py` y
`atrox/findings/store.py`: JSONL, sin base de datos, con acceso serializado
vía `asyncio.Lock`. El catálogo se mantiene en memoria para consultas
rápidas y se reescribe íntegro al sincronizar (los CVEs son datos públicos;
no requieren cifrado ADR-003).
"""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from atrox.threat_intel.models import CVEEntry, CveSyncStatus, CveSyncStatusEnum


class CveStore:
    """Persistencia JSONL del catálogo de CVEs + estado de última sincronización."""

    def __init__(self, store_path: Path, sync_status_path: Path) -> None:
        self._store_path = store_path
        self._sync_status_path = sync_status_path
        self._lock = asyncio.Lock()
        self._entries: dict[str, CVEEntry] | None = None
        self._store_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def store_path(self) -> Path:
        return self._store_path

    @property
    def sync_status_path(self) -> Path:
        return self._sync_status_path

    # -- Catálogo -------------------------------------------------------------

    async def _load(self) -> dict[str, CVEEntry]:
        if self._entries is not None:
            return self._entries

        entries: dict[str, CVEEntry] = {}
        if self._store_path.exists():
            async with self._lock:
                content = self._store_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                entry = CVEEntry.model_validate_json(line)
                entries[entry.cve_id] = entry

        self._entries = entries
        return entries

    async def _persist(self) -> None:
        """Escribe el catálogo completo en disco."""
        async with self._lock:
            with self._store_path.open("w", encoding="utf-8") as handle:
                for entry in sorted(self._entries.values(), key=lambda e: e.cve_id):
                    handle.write(entry.model_dump_json() + "\n")

    async def upsert(self, entry: CVEEntry) -> tuple[int, int]:
        """Inserta o actualiza un CVE. Retorna (agregados, actualizados)."""
        return await self.bulk_upsert([entry])

    async def bulk_upsert(self, entries: list[CVEEntry]) -> tuple[int, int]:
        """Inserta/actualiza un lote de CVEs de una sincronización.

        Retorna (cantidad de CVEs nuevos, cantidad de CVEs actualizados).
        """
        catalog = await self._load()
        added = 0
        updated = 0
        for entry in entries:
            if entry.cve_id in catalog:
                if catalog[entry.cve_id] != entry:
                    updated += 1
            else:
                added += 1
            catalog[entry.cve_id] = entry

        if added or updated:
            await self._persist()
        return added, updated

    async def get(self, cve_id: str) -> CVEEntry | None:
        catalog = await self._load()
        return catalog.get(cve_id)

    async def list_cves(
        self,
        cve_id: str | None = None,
        severity: str | None = None,
        query: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[CVEEntry]:
        """Lista el catálogo con filtros opcionales y paginación."""
        catalog = await self._load()
        results = [
            entry
            for entry in catalog.values()
            if _matches(entry, cve_id=cve_id, severity=severity, query=query)
        ]
        return sorted(results, key=lambda e: e.cve_id)[offset : offset + limit]

    async def count(
        self,
        cve_id: str | None = None,
        severity: str | None = None,
        query: str | None = None,
    ) -> int:
        catalog = await self._load()
        return sum(
            1
            for entry in catalog.values()
            if _matches(entry, cve_id=cve_id, severity=severity, query=query)
        )

    # -- Estado de sincronización ----------------------------------------------

    async def get_sync_status(self) -> CveSyncStatus:
        if not self._sync_status_path.exists():
            return CveSyncStatus(
                status=CveSyncStatusEnum.ERROR,
                last_attempt_at=datetime.now(UTC),
                last_error="Aún no se ha ejecutado ninguna sincronización",
            )
        async with self._lock:
            raw = self._sync_status_path.read_text(encoding="utf-8")
        return CveSyncStatus.model_validate_json(raw)

    async def save_sync_status(self, status: CveSyncStatus) -> None:
        async with self._lock:
            with self._sync_status_path.open("w", encoding="utf-8") as handle:
                handle.write(status.model_dump_json())


def _matches(
    entry: CVEEntry,
    cve_id: str | None,
    severity: str | None,
    query: str | None,
) -> bool:
    if cve_id and cve_id.upper() not in entry.cve_id.upper():
        return False
    if severity and (entry.cvss_severity or "").upper() != severity.upper():
        return False
    if query and query.lower() not in entry.description.lower():
        return False
    return True
