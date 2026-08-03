"""Servicio de persistencia con cifrado AES-256-GCM en reposo (HU-007)."""

from typing import Any
from uuid import UUID

from atrox.persistence.models import (
    CredentialCreate,
    CredentialRecord,
    FindingCreate,
    FindingRecord,
    ReportCreate,
    ReportRecord,
)
from atrox.persistence.store import JsonEntityStore
from atrox.scanner.models import VulnFinding
from atrox.security.sensitive_fields import SensitiveFieldEncryptor


class EncryptedPersistenceService:
    """Guarda hallazgos, credenciales y reportes cifrando campos sensibles."""

    def __init__(
        self,
        encryptor: SensitiveFieldEncryptor,
        findings_store: JsonEntityStore,
        credentials_store: JsonEntityStore,
        reports_store: JsonEntityStore,
    ) -> None:
        self._encryptor = encryptor
        self._findings = findings_store
        self._credentials = credentials_store
        self._reports = reports_store

    # ── Findings ──────────────────────────────────────────────────────────

    async def save_finding(self, data: FindingCreate | FindingRecord | dict) -> FindingRecord:
        if isinstance(data, FindingCreate):
            record = FindingRecord(**data.model_dump())
        elif isinstance(data, FindingRecord):
            record = data
        else:
            record = FindingRecord(**data)

        encrypted = self._encryptor.encrypt_fields("finding", record.model_dump(mode="json"))
        await self._findings.upsert(record.id, encrypted)
        return FindingRecord.model_validate(
            self._encryptor.decrypt_fields("finding", encrypted)
        )

    async def save_findings_from_vulnscan(
        self,
        findings: list[VulnFinding] | list[dict[str, Any]],
        job_id: UUID | None = None,
    ) -> list[FindingRecord]:
        saved: list[FindingRecord] = []
        for item in findings:
            if isinstance(item, VulnFinding):
                payload = item.model_dump(mode="json")
            else:
                payload = dict(item)

            evidence = ""
            extracted = payload.get("extracted_results") or []
            if extracted:
                evidence = "\n".join(str(x) for x in extracted)

            create = FindingCreate(
                name=payload.get("name", "unknown"),
                severity=str(payload.get("severity", "unknown")),
                host=payload.get("host", ""),
                matched_at=payload.get("matched_at", ""),
                template_id=payload.get("template_id", ""),
                tags=list(payload.get("tags") or []),
                job_id=job_id,
                description=payload.get("description") or None,
                evidence=evidence or None,
                raw_output=payload.get("matched_at") or None,
            )
            saved.append(await self.save_finding(create))
        return saved

    async def list_findings(self, *, decrypt: bool = True) -> list[FindingRecord]:
        rows = await self._findings.list_all()
        return [self._to_finding(row, decrypt=decrypt) for row in rows]

    async def get_finding(self, finding_id: UUID, *, decrypt: bool = True) -> FindingRecord | None:
        row = await self._findings.get(finding_id)
        if row is None:
            return None
        return self._to_finding(row, decrypt=decrypt)

    def _to_finding(self, row: dict[str, Any], *, decrypt: bool) -> FindingRecord:
        data = self._encryptor.decrypt_fields("finding", row) if decrypt else row
        return FindingRecord.model_validate(data)

    # ── Credentials ───────────────────────────────────────────────────────

    async def save_credential(self, data: CredentialCreate | CredentialRecord) -> CredentialRecord:
        record = (
            CredentialRecord(**data.model_dump())
            if isinstance(data, CredentialCreate)
            else data
        )
        encrypted = self._encryptor.encrypt_fields("credential", record.model_dump(mode="json"))
        await self._credentials.upsert(record.id, encrypted)
        return CredentialRecord.model_validate(
            self._encryptor.decrypt_fields("credential", encrypted)
        )

    async def list_credentials(self, *, decrypt: bool = True) -> list[CredentialRecord]:
        rows = await self._credentials.list_all()
        return [self._to_credential(row, decrypt=decrypt) for row in rows]

    async def get_credential(
        self, credential_id: UUID, *, decrypt: bool = True
    ) -> CredentialRecord | None:
        row = await self._credentials.get(credential_id)
        if row is None:
            return None
        return self._to_credential(row, decrypt=decrypt)

    def _to_credential(self, row: dict[str, Any], *, decrypt: bool) -> CredentialRecord:
        data = self._encryptor.decrypt_fields("credential", row) if decrypt else row
        return CredentialRecord.model_validate(data)

    # ── Reports ───────────────────────────────────────────────────────────

    async def save_report(self, data: ReportCreate | ReportRecord) -> ReportRecord:
        record = ReportRecord(**data.model_dump()) if isinstance(data, ReportCreate) else data
        encrypted = self._encryptor.encrypt_fields("report", record.model_dump(mode="json"))
        await self._reports.upsert(record.id, encrypted)
        return ReportRecord.model_validate(
            self._encryptor.decrypt_fields("report", encrypted)
        )

    async def list_reports(self, *, decrypt: bool = True) -> list[ReportRecord]:
        rows = await self._reports.list_all()
        return [self._to_report(row, decrypt=decrypt) for row in rows]

    async def get_report(self, report_id: UUID, *, decrypt: bool = True) -> ReportRecord | None:
        row = await self._reports.get(report_id)
        if row is None:
            return None
        return self._to_report(row, decrypt=decrypt)

    def _to_report(self, row: dict[str, Any], *, decrypt: bool) -> ReportRecord:
        data = self._encryptor.decrypt_fields("report", row) if decrypt else row
        return ReportRecord.model_validate(data)

    # ── Jobs: cifrar resultado sensible en memoria / respuesta ────────────

    def encrypt_job_result(self, result: dict[str, Any]) -> dict[str, Any]:
        """Cifra campos sensibles de hallazgos dentro del result del job."""
        output = dict(result)
        findings = output.get("findings")
        if not isinstance(findings, list):
            return output

        encrypted_findings: list[dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, dict):
                encrypted_findings.append(finding)
                continue

            normalized = dict(finding)
            if "evidence" not in normalized and normalized.get("extracted_results"):
                normalized["evidence"] = "\n".join(
                    str(x) for x in normalized["extracted_results"]
                )
            if "raw_output" not in normalized and normalized.get("matched_at"):
                normalized["raw_output"] = str(normalized["matched_at"])

            encrypted_findings.append(
                self._encryptor.encrypt_fields("finding", normalized)
            )

        output["findings"] = encrypted_findings
        return output

    def decrypt_job_result(self, result: dict[str, Any]) -> dict[str, Any]:
        output = dict(result)
        findings = output.get("findings")
        if not isinstance(findings, list):
            return output

        decrypted: list[dict[str, Any]] = []
        for finding in findings:
            if isinstance(finding, dict):
                decrypted.append(self._encryptor.decrypt_fields("finding", finding))
            else:
                decrypted.append(finding)
        output["findings"] = decrypted
        return output

    @property
    def findings_store(self) -> JsonEntityStore:
        return self._findings

    @property
    def credentials_store(self) -> JsonEntityStore:
        return self._credentials

    @property
    def reports_store(self) -> JsonEntityStore:
        return self._reports
