"""Almacén append-only de marcados manuales de falsos positivos (HU-022).

Mismo patrón que `atrox/security/audit_service.py::AuditLogStore` (JSONL,
append-only, sin base de datos). El sub-objeto `finding` se cifra vía
`SensitiveFieldEncryptor` cuando hay servicio de cifrado configurado
(ADR-003) — el marcado incluye la evidencia/descripción del hallazgo, que ya
está registrada como sensible en `sensitive_fields.py` bajo la categoría
"finding".
"""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from atrox.findings.models import FalsePositiveMark
from atrox.scanner.models import VulnFinding
from atrox.security.sensitive_fields import SensitiveFieldEncryptor


class FalsePositiveStore:
    """Persistencia de marcados de falsos positivos — también sirve como
    dataset etiquetado para reentrenamiento/heurística futura (DoD HU-022),
    en el mismo espíritu que `tests/fixtures/scoring_dataset.py` de HU-016.
    """

    def __init__(
        self,
        store_path: Path,
        encryptor: SensitiveFieldEncryptor | None = None,
    ) -> None:
        self._store_path = store_path
        self._encryptor = encryptor
        self._lock = asyncio.Lock()
        self._store_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def store_path(self) -> Path:
        return self._store_path

    async def mark(
        self,
        scan_id: str,
        finding_id: str,
        finding: VulnFinding,
        user: str,
        reason: str | None = None,
    ) -> FalsePositiveMark:
        """Persiste el marcado. Registro append-only: no hay operación de desmarcado."""
        record = FalsePositiveMark(
            scan_id=scan_id,
            finding_id=finding_id,
            matched_at=finding.matched_at,
            finding=finding,
            user=user,
            reason=reason,
            marked_at=datetime.now(UTC),
        )

        payload = record.model_dump(mode="json")
        if self._encryptor is not None:
            payload["finding"] = self._encryptor.encrypt_fields("finding", payload["finding"])

        async with self._lock:
            with self._store_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

        return record

    async def _read_all_raw(self) -> list[dict[str, Any]]:
        if not self._store_path.exists():
            return []

        async with self._lock:
            content = self._store_path.read_text(encoding="utf-8")

        entries: list[dict[str, Any]] = []
        for line in content.splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
        return entries

    async def list_marks(self, scan_id: str | None = None) -> list[FalsePositiveMark]:
        """Retorna los marcados persistidos, opcionalmente filtrados por scan_id."""
        marks: list[FalsePositiveMark] = []
        for raw in await self._read_all_raw():
            if scan_id is not None and raw["scan_id"] != scan_id:
                continue

            payload = dict(raw)
            if self._encryptor is not None:
                payload["finding"] = self._encryptor.decrypt_fields("finding", payload["finding"])

            marks.append(FalsePositiveMark.model_validate(payload))
        return marks
