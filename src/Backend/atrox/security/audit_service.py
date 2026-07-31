import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from atrox.security.audit_models import AuditEvent, SignedAuditEntry, TamperDetectedError
from atrox.security.audit_signer import AuditSigner


class AuditLogStore:
    """Almacén append-only de entradas de auditoría firmadas (JSONL)."""

    def __init__(self, log_path: Path, retention_days: int) -> None:
        self._log_path = log_path
        self._retention_days = retention_days
        self._lock = asyncio.Lock()
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def log_path(self) -> Path:
        return self._log_path

    async def append(self, entry: SignedAuditEntry) -> None:
        line = json.dumps(entry.model_dump(mode="json"), ensure_ascii=False)
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

    async def rewrite(self, entries: list[dict[str, Any]]) -> None:
        async with self._lock:
            with self._log_path.open("w", encoding="utf-8") as handle:
                for entry in entries:
                    handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    async def apply_retention(self) -> int:
        """Elimina entradas más antiguas que el periodo de retención configurado."""
        cutoff = datetime.now(UTC) - timedelta(days=self._retention_days)
        entries = await self.read_all()
        kept: list[dict[str, Any]] = []
        removed = 0

        for raw in entries:
            ts = datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            if ts >= cutoff:
                kept.append(raw)
            else:
                removed += 1

        if removed:
            await self.rewrite(kept)
        return removed


class AuditLogService:
    """Servicio de log de auditoría inmutable con firmas criptográficas."""

    def __init__(self, store: AuditLogStore, signer: AuditSigner) -> None:
        self._store = store
        self._signer = signer

    async def record(
        self,
        user: str,
        action: str,
        resource: str,
        metadata: dict[str, Any] | None = None,
    ) -> SignedAuditEntry:
        event = AuditEvent(
            id=uuid4(),
            timestamp=datetime.now(UTC),
            user=user,
            action=action,
            resource=resource,
            metadata=metadata or {},
        )

        payload = event.model_dump(mode="json")
        signature = self._signer.sign(payload)
        signed = SignedAuditEntry(signature=signature, **event.model_dump())

        await self._store.append(signed)
        return signed

    async def query(
        self,
        from_date: datetime | None = None,
        to_date: datetime | None = None,
        user: str | None = None,
        action: str | None = None,
        verify: bool = True,
    ) -> tuple[list[SignedAuditEntry], int, int]:
        """
        Consulta entradas filtradas por rango de fechas, usuario y acción.
        Retorna (entradas, verificadas, alteradas).
        """
        raw_entries = await self._store.read_all()
        verified_count = 0
        tampered_count = 0
        results: list[SignedAuditEntry] = []

        for raw in raw_entries:
            entry = SignedAuditEntry.model_validate(raw)
            ts = entry.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)

            if from_date and ts < _ensure_utc(from_date):
                continue
            if to_date and ts > _ensure_utc(to_date):
                continue
            if user and entry.user != user:
                continue
            if action and entry.action != action:
                continue

            if verify:
                if self._signer.verify(raw):
                    verified_count += 1
                else:
                    tampered_count += 1

            results.append(entry)

        return results, verified_count, tampered_count

    async def verify_integrity(self) -> list[str]:
        """Retorna IDs de entradas con firma inválida (tamper detection)."""
        tampered_ids: list[str] = []
        for raw in await self._store.read_all():
            if not self._signer.verify(raw):
                tampered_ids.append(str(raw.get("id", "unknown")))
        return tampered_ids

    async def verify_integrity_or_raise(self) -> None:
        tampered = await self.verify_integrity()
        if tampered:
            raise TamperDetectedError(
                f"Se detectaron {len(tampered)} entradas alteradas: {', '.join(tampered)}"
            )

    async def purge_expired(self) -> int:
        return await self._store.apply_retention()


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
