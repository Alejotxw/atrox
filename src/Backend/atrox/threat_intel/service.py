"""Servicio de sincronización de la base de amenazas NVD (HU-005 / RF-010).

`NvdSyncService.sync_once()` ejecuta una sincronización completa: consulta
la API NVD (delta desde la última sincronización), indexa los CVEs en el
`CveStore` y registra el estado en el log de última sincronización.

Los errores de red se capturan y persisten en el estado (`last_error`) sin
propagarse, de modo que un fallo de NVD jamás interrumpe la cola de
escaneos activos. El bucle `run_daily()` es el scheduler usado por la
lifespan de la aplicación.
"""

import asyncio
import logging
from datetime import UTC, datetime
from pathlib import Path

from atrox.config import get_settings
from atrox.threat_intel.cve_store import CveStore
from atrox.threat_intel.models import CveSyncStatus, CveSyncStatusEnum
from atrox.threat_intel.nvd_client import NvdClient, NvdClientError

logger = logging.getLogger(__name__)


class SyncInProgressError(Exception):
    """Ya hay una sincronización en curso; no se permite ejecución paralela."""


class NvdSyncService:
    """Orquesta el consumo de la API NVD y la indexación del catálogo."""

    def __init__(self, client: NvdClient, store: CveStore) -> None:
        self._client = client
        self._store = store
        self._lock = asyncio.Lock()

    @property
    def store(self) -> CveStore:
        return self._store

    async def get_status(self) -> CveSyncStatus:
        return await self._store.get_sync_status()

    async def sync_once(self, force_full: bool = False) -> CveSyncStatus:
        """Ejecuta una sincronización manual o programada.

        Raises:
            SyncInProgressError: Si otra sincronización está en curso.
        """
        if self._lock.locked():
            raise SyncInProgressError("Ya hay una sincronización NVD en curso")
        async with self._lock:
            return await self._sync_locked(force_full=force_full)

    async def sync_once_safe(self) -> CveSyncStatus | None:
        """Igual que `sync_once` pero nunca propaga excepciones (uso en lifespan)."""
        try:
            return await self.sync_once()
        except SyncInProgressError:
            return None
        except Exception as exc:  # pragma: no cover - salvaguarda del scheduler
            logger.exception("Fallo inesperado en sincronización NVD")
            await self._record_failure(datetime.now(UTC), str(exc))
            return None

    async def run_daily(self, interval_seconds: int) -> None:
        """Bucle del scheduler: sincroniza cada `interval_seconds`.

        Duerme primero, de modo que el arranque de la app no hace llamadas
        de red (la primera sincronización se dispara manualmente o vía API).
        """
        while True:
            await asyncio.sleep(interval_seconds)
            await self.sync_once_safe()

    async def _sync_locked(self, force_full: bool = False) -> CveSyncStatus:
        last_status = await self._store.get_sync_status()
        since: datetime | None = None if force_full else last_status.last_success_at
        attempt_at = datetime.now(UTC)

        try:
            entries = await self._client.fetch_changes(since=since)
        except (NvdClientError, OSError) as exc:
            logger.warning("Sincronización NVD falló (sin interrumpir escaneos): %s", exc)
            return await self._record_failure(attempt_at, str(exc))
        except Exception as exc:
            logger.exception("Error inesperado consultando NVD")
            return await self._record_failure(attempt_at, str(exc))

        added, updated = await self._store.bulk_upsert(entries)
        total = await self._store.count()

        status = CveSyncStatus(
            status=CveSyncStatusEnum.OK,
            last_attempt_at=attempt_at,
            last_success_at=attempt_at,
            cves_total=total,
            cves_added=added,
            cves_updated=updated,
        )
        await self._store.save_sync_status(status)
        logger.info(
            "NVD sincronizado: %d agregados, %d actualizados (total %d)",
            added,
            updated,
            total,
        )
        return status

    async def _record_failure(self, attempt_at: datetime, error: str) -> CveSyncStatus:
        last_status = await self._store.get_sync_status()
        status = CveSyncStatus(
            status=CveSyncStatusEnum.ERROR,
            last_attempt_at=attempt_at,
            last_success_at=last_status.last_success_at,
            cves_total=last_status.cves_total,
            last_error=error,
        )
        await self._store.save_sync_status(status)
        return status


def build_nvd_sync_service() -> NvdSyncService:
    """Factory que construye el servicio desde la configuración centralizada."""
    settings = get_settings()
    store = CveStore(
        store_path=Path(settings.nvd_store_path),
        sync_status_path=Path(settings.nvd_sync_status_path),
    )
    client = NvdClient(
        api_url=settings.nvd_api_url,
        api_key=settings.nvd_api_key,
        timeout_seconds=settings.nvd_request_timeout_seconds,
    )
    return NvdSyncService(client=client, store=store)
