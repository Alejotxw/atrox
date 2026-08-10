"""Persistencia JSONL de cuentas de usuario (aprobadas desde solicitudes de acceso).

Mismo patrón mutable que `atrox/threat_intel/cve_store.py::CveStore` y
`atrox/access_requests/store.py`: catálogo en memoria cacheado, reescrito
íntegro en cada mutación (estado, notas de moderación).
"""

import asyncio
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from atrox.access_requests.models import AccessRequest
from atrox.accounts.models import Account, AccountStatus, ModerationNote, ModerationNoteKind
from atrox.security.sensitive_fields import SensitiveFieldEncryptor

_USERNAME_SANITIZE_PATTERN = re.compile(r"[^a-z0-9.]+")


class AccountNotFoundError(LookupError):
    """La cuenta indicada no existe."""


class AccountStore:
    """Persistencia de cuentas de usuario, con cifrado opcional (ADR-003)."""

    def __init__(
        self,
        store_path: Path,
        encryptor: SensitiveFieldEncryptor | None = None,
        reserved_usernames: frozenset[str] = frozenset(),
    ) -> None:
        self._store_path = store_path
        self._encryptor = encryptor
        # Evita que un username auto-generado (desde el email de la solicitud)
        # colisione con el sysadmin único — de lo contrario esa cuenta quedaría
        # enrutada al flujo de login TOTP del admin en vez del suyo propio.
        self._reserved_usernames = {u.lower() for u in reserved_usernames}
        self._lock = asyncio.Lock()
        self._entries: dict[UUID, Account] | None = None
        self._store_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def store_path(self) -> Path:
        return self._store_path

    async def _load(self) -> dict[UUID, Account]:
        if self._entries is not None:
            return self._entries

        entries: dict[UUID, Account] = {}
        if self._store_path.exists():
            async with self._lock:
                content = self._store_path.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                raw: dict[str, Any] = json.loads(line)
                if self._encryptor is not None:
                    raw = self._encryptor.decrypt_fields("account", raw)
                record = Account.model_validate(raw)
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
                        payload = self._encryptor.encrypt_fields("account", payload)
                    handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    async def _generate_unique_username(self, email: str, catalog: dict[UUID, Account]) -> str:
        local_part = email.split("@", 1)[0].lower()
        base = _USERNAME_SANITIZE_PATTERN.sub("", local_part) or "usuario"
        taken = {account.username for account in catalog.values()} | self._reserved_usernames

        if base not in taken:
            return base
        suffix = 2
        while f"{base}{suffix}" in taken:
            suffix += 1
        return f"{base}{suffix}"

    async def create_from_request(self, request: AccessRequest, password_hash: str) -> Account:
        catalog = await self._load()
        username = await self._generate_unique_username(request.email, catalog)
        account = Account(
            username=username,
            password_hash=password_hash,
            full_name=request.full_name,
            email=request.email,
            organization=request.organization,
            role=request.role,
            access_request_id=request.id,
        )
        catalog[account.id] = account
        await self._persist()
        return account

    async def get(self, account_id: UUID) -> Account | None:
        catalog = await self._load()
        return catalog.get(account_id)

    async def get_by_username(self, username: str) -> Account | None:
        catalog = await self._load()
        for account in catalog.values():
            if account.username == username:
                return account
        return None

    async def list_all(self) -> list[Account]:
        """Lista todas las cuentas, más recientes primero."""
        catalog = await self._load()
        return sorted(catalog.values(), key=lambda a: a.created_at, reverse=True)

    async def set_status(self, account_id: UUID, status: AccountStatus) -> Account:
        catalog = await self._load()
        record = catalog.get(account_id)
        if record is None:
            raise AccountNotFoundError(f"Cuenta no encontrada: {account_id}")

        updated = record.model_copy(update={"status": status})
        catalog[account_id] = updated
        await self._persist()
        return updated

    async def add_moderation_note(
        self, account_id: UUID, kind: ModerationNoteKind, reason: str, created_by: str
    ) -> Account:
        catalog = await self._load()
        record = catalog.get(account_id)
        if record is None:
            raise AccountNotFoundError(f"Cuenta no encontrada: {account_id}")

        note = ModerationNote(kind=kind, reason=reason, created_by=created_by, created_at=datetime.now(UTC))
        updated = record.model_copy(update={"moderation_notes": [*record.moderation_notes, note]})
        catalog[account_id] = updated
        await self._persist()
        return updated
