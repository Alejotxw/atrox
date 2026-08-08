"""Persistencia JSONL de solicitudes de acceso a la plataforma (landing page).

Mismo patrón que `atrox/threat_intel/cve_store.py::CveStore`: catálogo en
memoria (`dict` cacheado) cargado una vez desde disco y reescrito íntegro en
cada mutación — a diferencia de un store append-only, las solicitudes
cambian de estado (pendiente → aprobada/rechazada) a lo largo de su vida.
No hay envío de correo (sin infraestructura SMTP en el proyecto) — el
administrador revisa y decide vía `GET/POST /api/access-requests/...`
(protegido con MFA).
"""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from atrox.access_requests.models import AccessRequest, AccessRequestCreate, AccessRequestStatus
from atrox.security.sensitive_fields import SensitiveFieldEncryptor


class AccessRequestNotFoundError(LookupError):
    """La solicitud de acceso indicada no existe."""


class AccessRequestStore:
    """Persistencia de solicitudes de acceso, con cifrado opcional (ADR-003)."""

    def __init__(
        self,
        store_path: Path,
        encryptor: SensitiveFieldEncryptor | None = None,
    ) -> None:
        self._store_path = store_path
        self._encryptor = encryptor
        self._lock = asyncio.Lock()
        self._entries: dict[UUID, AccessRequest] | None = None
        self._store_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def store_path(self) -> Path:
        return self._store_path

    async def _load(self) -> dict[UUID, AccessRequest]:
        if self._entries is not None:
            return self._entries

        entries: dict[UUID, AccessRequest] = {}
        if self._store_path.exists():
            async with self._lock:
                content = self._store_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                raw: dict[str, Any] = json.loads(line)
                if self._encryptor is not None:
                    raw = self._encryptor.decrypt_fields("access_request", raw)
                record = AccessRequest.model_validate(raw)
                entries[record.id] = record

        self._entries = entries
        return entries

    async def _persist(self) -> None:
        assert self._entries is not None
        async with self._lock:
            with self._store_path.open("w", encoding="utf-8") as handle:
                for record in self._entries.values():
                    payload = record.model_dump(mode="json")
                    if self._encryptor is not None:
                        payload = self._encryptor.encrypt_fields("access_request", payload)
                    handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    async def create(self, data: AccessRequestCreate) -> AccessRequest:
        catalog = await self._load()
        record = AccessRequest(**data.model_dump())
        catalog[record.id] = record
        await self._persist()
        return record

    async def get(self, request_id: UUID) -> AccessRequest | None:
        catalog = await self._load()
        return catalog.get(request_id)

    async def list_all(self) -> list[AccessRequest]:
        """Lista todas las solicitudes, más recientes primero."""
        catalog = await self._load()
        return sorted(catalog.values(), key=lambda r: r.created_at, reverse=True)

    async def mark_approved(self, request_id: UUID, account_id: UUID) -> AccessRequest:
        return await self._update_status(
            request_id, status=AccessRequestStatus.APPROVED, account_id=account_id
        )

    async def mark_rejected(self, request_id: UUID, reason: str | None) -> AccessRequest:
        return await self._update_status(
            request_id, status=AccessRequestStatus.REJECTED, review_reason=reason
        )

    async def _update_status(
        self,
        request_id: UUID,
        status: AccessRequestStatus,
        account_id: UUID | None = None,
        review_reason: str | None = None,
    ) -> AccessRequest:
        catalog = await self._load()
        record = catalog.get(request_id)
        if record is None:
            raise AccessRequestNotFoundError(f"Solicitud de acceso no encontrada: {request_id}")

        updated = record.model_copy(
            update={
                "status": status,
                "reviewed_at": datetime.now(UTC),
                "account_id": account_id,
                "review_reason": review_reason,
            }
        )
        catalog[request_id] = updated
        await self._persist()
        return updated
