"""Tests unitarios del almacén de marcados de falsos positivos (HU-022)."""

import asyncio
import base64
import os
from pathlib import Path

import pytest

from atrox.findings.store import FalsePositiveStore
from atrox.scanner.models import VulnFinding, VulnSeverity
from atrox.security.encryption import get_encryption_service
from atrox.security.sensitive_fields import SensitiveFieldEncryptor


def _finding(**overrides) -> VulnFinding:
    data = dict(
        template_id="cve-2021-41773",
        name="Apache Path Traversal",
        severity=VulnSeverity.CRITICAL,
        host="http://example.com",
        matched_at="http://example.com/traversal",
        tags=["cve", "rce"],
        description="Path traversal confirmado.",
        extracted_results=["root:x:0:0:root:/root:/bin/bash"],
    )
    data.update(overrides)
    return VulnFinding(**data)


def _random_master_key() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


@pytest.fixture
def store(tmp_path: Path) -> FalsePositiveStore:
    return FalsePositiveStore(store_path=tmp_path / "false_positives.jsonl")


# -- La accion persiste estado false_positive con usuario y timestamp (spec) ---


class TestMarkPersistsUserAndTimestamp:
    def test_mark_returns_record_with_user_and_marked_at(self, store: FalsePositiveStore) -> None:
        mark = asyncio.run(
            store.mark(scan_id="scan-1", finding_id="cve-2021-41773", finding=_finding(), user="analyst1")
        )

        assert mark.user == "analyst1"
        assert mark.marked_at is not None
        assert mark.scan_id == "scan-1"
        assert mark.finding_id == "cve-2021-41773"

    def test_mark_persists_across_store_instances(self, tmp_path: Path) -> None:
        path = tmp_path / "false_positives.jsonl"
        store1 = FalsePositiveStore(store_path=path)
        asyncio.run(store1.mark(scan_id="scan-1", finding_id="cve-x", finding=_finding(), user="analyst1"))

        store2 = FalsePositiveStore(store_path=path)
        marks = asyncio.run(store2.list_marks())

        assert len(marks) == 1
        assert marks[0].finding_id == "cve-x"

    def test_mark_captures_optional_reason(self, store: FalsePositiveStore) -> None:
        mark = asyncio.run(
            store.mark(
                scan_id="scan-1",
                finding_id="cve-x",
                finding=_finding(),
                user="analyst1",
                reason="Confirmado como banner grab genérico",
            )
        )

        assert mark.reason == "Confirmado como banner grab genérico"


class TestListMarks:
    def test_list_marks_filters_by_scan_id(self, store: FalsePositiveStore) -> None:
        asyncio.run(store.mark(scan_id="scan-1", finding_id="a", finding=_finding(), user="u1"))
        asyncio.run(store.mark(scan_id="scan-2", finding_id="b", finding=_finding(), user="u1"))

        marks = asyncio.run(store.list_marks(scan_id="scan-1"))

        assert len(marks) == 1
        assert marks[0].finding_id == "a"

    def test_list_marks_without_scan_id_returns_all(self, store: FalsePositiveStore) -> None:
        asyncio.run(store.mark(scan_id="scan-1", finding_id="a", finding=_finding(), user="u1"))
        asyncio.run(store.mark(scan_id="scan-2", finding_id="b", finding=_finding(), user="u1"))

        marks = asyncio.run(store.list_marks())

        assert len(marks) == 2

    def test_list_marks_empty_when_nothing_marked(self, store: FalsePositiveStore) -> None:
        assert asyncio.run(store.list_marks()) == []

    def test_list_marks_includes_full_finding_for_retraining_dataset(
        self, store: FalsePositiveStore
    ) -> None:
        """DoD: dato disponible para reentrenamiento/heurística futura."""
        asyncio.run(
            store.mark(
                scan_id="scan-1",
                finding_id="cve-x",
                finding=_finding(severity=VulnSeverity.HIGH, tags=["cve", "sqli"]),
                user="analyst1",
            )
        )

        marks = asyncio.run(store.list_marks())

        assert marks[0].finding.severity == VulnSeverity.HIGH
        assert marks[0].finding.tags == ["cve", "sqli"]


# -- Cifrado en reposo (ADR-003) cuando hay servicio de cifrado configurado ----


class TestFalsePositiveEncryptionAtRest:
    def test_finding_description_is_encrypted_on_disk_when_encryptor_configured(
        self, tmp_path: Path
    ) -> None:
        encryption = get_encryption_service(_random_master_key())
        encryptor = SensitiveFieldEncryptor(encryption)
        path = tmp_path / "false_positives.jsonl"
        store = FalsePositiveStore(store_path=path, encryptor=encryptor)

        asyncio.run(
            store.mark(
                scan_id="scan-1",
                finding_id="cve-x",
                finding=_finding(description="Texto sensible en claro"),
                user="analyst1",
            )
        )

        raw_content = path.read_text(encoding="utf-8")
        assert "Texto sensible en claro" not in raw_content

    def test_finding_is_decrypted_when_read_back_via_list_marks(self, tmp_path: Path) -> None:
        encryption = get_encryption_service(_random_master_key())
        encryptor = SensitiveFieldEncryptor(encryption)
        path = tmp_path / "false_positives.jsonl"
        store = FalsePositiveStore(store_path=path, encryptor=encryptor)

        asyncio.run(
            store.mark(
                scan_id="scan-1",
                finding_id="cve-x",
                finding=_finding(description="Texto sensible en claro"),
                user="analyst1",
            )
        )

        marks = asyncio.run(store.list_marks())

        assert marks[0].finding.description == "Texto sensible en claro"
