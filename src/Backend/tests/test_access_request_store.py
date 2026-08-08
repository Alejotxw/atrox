"""Tests unitarios del almacén de solicitudes de acceso (landing page pre-login)."""

import asyncio
import base64
import os
from pathlib import Path

import pytest

from atrox.access_requests.models import AccessRequestCreate
from atrox.access_requests.store import AccessRequestStore
from atrox.security.encryption import get_encryption_service
from atrox.security.sensitive_fields import SensitiveFieldEncryptor


def _request(**overrides) -> AccessRequestCreate:
    data = dict(
        full_name="Ana Torres",
        email="ana.torres@uide.edu.ec",
        organization="UIDE - Facultad de Ingeniería",
        role="Estudiante",
        reason="Necesito acceso para el proyecto de tesis sobre pentesting.",
    )
    data.update(overrides)
    return AccessRequestCreate(**data)


def _random_master_key() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


@pytest.fixture
def store(tmp_path: Path) -> AccessRequestStore:
    return AccessRequestStore(store_path=tmp_path / "access_requests.jsonl")


class TestCreatePersistsRequest:
    def test_create_returns_record_with_id_and_timestamp(self, store: AccessRequestStore) -> None:
        record = asyncio.run(store.create(_request()))

        assert record.id is not None
        assert record.created_at is not None
        assert record.full_name == "Ana Torres"
        assert record.email == "ana.torres@uide.edu.ec"

    def test_create_persists_across_store_instances(self, tmp_path: Path) -> None:
        path = tmp_path / "access_requests.jsonl"
        store1 = AccessRequestStore(store_path=path)
        asyncio.run(store1.create(_request(email="a@uide.edu.ec")))

        store2 = AccessRequestStore(store_path=path)
        requests = asyncio.run(store2.list_all())

        assert len(requests) == 1
        assert requests[0].email == "a@uide.edu.ec"


class TestListAll:
    def test_list_all_empty_when_nothing_submitted(self, store: AccessRequestStore) -> None:
        assert asyncio.run(store.list_all()) == []

    def test_list_all_returns_most_recent_first(self, store: AccessRequestStore) -> None:
        asyncio.run(store.create(_request(full_name="Primero")))
        asyncio.run(store.create(_request(full_name="Segundo")))

        requests = asyncio.run(store.list_all())

        assert len(requests) == 2
        assert requests[0].full_name == "Segundo"
        assert requests[1].full_name == "Primero"


class TestAccessRequestEncryptionAtRest:
    def test_reason_is_encrypted_on_disk_when_encryptor_configured(self, tmp_path: Path) -> None:
        encryption = get_encryption_service(_random_master_key())
        encryptor = SensitiveFieldEncryptor(encryption)
        path = tmp_path / "access_requests.jsonl"
        store = AccessRequestStore(store_path=path, encryptor=encryptor)

        asyncio.run(store.create(_request(reason="Motivo confidencial de la solicitud")))

        raw_content = path.read_text(encoding="utf-8")
        assert "Motivo confidencial de la solicitud" not in raw_content
        assert "Ana Torres" not in raw_content

    def test_request_is_decrypted_when_read_back_via_list_all(self, tmp_path: Path) -> None:
        encryption = get_encryption_service(_random_master_key())
        encryptor = SensitiveFieldEncryptor(encryption)
        path = tmp_path / "access_requests.jsonl"
        store = AccessRequestStore(store_path=path, encryptor=encryptor)

        asyncio.run(store.create(_request(reason="Motivo confidencial de la solicitud")))

        requests = asyncio.run(store.list_all())

        assert requests[0].reason == "Motivo confidencial de la solicitud"
        assert requests[0].full_name == "Ana Torres"
