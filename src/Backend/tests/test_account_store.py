"""Tests unitarios del almacén de cuentas de usuario (super admin)."""

import asyncio
import base64
import os
from pathlib import Path

import pytest

from atrox.access_requests.models import AccessRequest
from atrox.accounts.models import AccountStatus, ModerationNoteKind
from atrox.accounts.store import AccountNotFoundError, AccountStore
from atrox.security.encryption import get_encryption_service
from atrox.security.sensitive_fields import SensitiveFieldEncryptor


def _request(**overrides) -> AccessRequest:
    data = dict(
        full_name="Ana Torres",
        email="ana.torres@uide.edu.ec",
        organization="UIDE - Facultad de Ingeniería",
        role="Estudiante",
        reason="Necesito acceso para el proyecto de tesis sobre pentesting.",
    )
    data.update(overrides)
    return AccessRequest(**data)


def _random_master_key() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


@pytest.fixture
def store(tmp_path: Path) -> AccountStore:
    return AccountStore(store_path=tmp_path / "accounts.jsonl")


class TestCreateFromRequest:
    def test_create_derives_username_from_email(self, store: AccountStore) -> None:
        account = asyncio.run(store.create_from_request(_request(), password_hash="hash1"))

        assert account.username == "ana.torres"
        assert account.full_name == "Ana Torres"
        assert account.status == AccountStatus.ACTIVE
        assert account.access_request_id is not None

    def test_create_deduplicates_username_on_collision(self, store: AccountStore) -> None:
        asyncio.run(store.create_from_request(_request(email="ana.torres@uide.edu.ec"), password_hash="hash1"))
        second = asyncio.run(
            store.create_from_request(_request(email="ana.torres@gmail.com"), password_hash="hash2")
        )

        assert second.username == "ana.torres2"

    def test_create_avoids_colliding_with_reserved_admin_username(self, tmp_path: Path) -> None:
        """Si el email genera un username == al del sysadmin, no debe colisionar —
        de lo contrario esa cuenta quedaría enrutada al flujo de login TOTP del
        admin en vez del suyo propio (ver atrox/api/auth.py::login_step1)."""
        store = AccountStore(store_path=tmp_path / "accounts.jsonl", reserved_usernames=frozenset({"sysadmin"}))

        account = asyncio.run(
            store.create_from_request(_request(email="sysadmin@uide.edu.ec"), password_hash="hash1")
        )

        assert account.username != "sysadmin"
        assert account.username == "sysadmin2"

    def test_create_persists_across_store_instances(self, tmp_path: Path) -> None:
        path = tmp_path / "accounts.jsonl"
        store1 = AccountStore(store_path=path)
        asyncio.run(store1.create_from_request(_request(), password_hash="hash1"))

        store2 = AccountStore(store_path=path)
        accounts = asyncio.run(store2.list_all())

        assert len(accounts) == 1
        assert accounts[0].username == "ana.torres"


class TestGetByUsername:
    def test_returns_matching_account(self, store: AccountStore) -> None:
        created = asyncio.run(store.create_from_request(_request(), password_hash="hash1"))

        found = asyncio.run(store.get_by_username("ana.torres"))

        assert found is not None
        assert found.id == created.id

    def test_returns_none_when_not_found(self, store: AccountStore) -> None:
        assert asyncio.run(store.get_by_username("nadie")) is None


class TestSetStatus:
    def test_suspend_then_reactivate(self, store: AccountStore) -> None:
        account = asyncio.run(store.create_from_request(_request(), password_hash="hash1"))

        suspended = asyncio.run(store.set_status(account.id, AccountStatus.SUSPENDED))
        assert suspended.status == AccountStatus.SUSPENDED

        reactivated = asyncio.run(store.set_status(account.id, AccountStatus.ACTIVE))
        assert reactivated.status == AccountStatus.ACTIVE

    def test_delete_sets_deleted_status(self, store: AccountStore) -> None:
        account = asyncio.run(store.create_from_request(_request(), password_hash="hash1"))

        deleted = asyncio.run(store.set_status(account.id, AccountStatus.DELETED))

        assert deleted.status == AccountStatus.DELETED

    def test_raises_for_unknown_account(self, store: AccountStore) -> None:
        import uuid

        with pytest.raises(AccountNotFoundError):
            asyncio.run(store.set_status(uuid.uuid4(), AccountStatus.SUSPENDED))


class TestModerationNotes:
    def test_add_warning_appends_to_history(self, store: AccountStore) -> None:
        account = asyncio.run(store.create_from_request(_request(), password_hash="hash1"))

        updated = asyncio.run(
            store.add_moderation_note(
                account.id, kind=ModerationNoteKind.WARNING, reason="Uso sospechoso detectado", created_by="sysadmin"
            )
        )

        assert len(updated.moderation_notes) == 1
        assert updated.moderation_notes[0].kind == ModerationNoteKind.WARNING
        assert updated.moderation_notes[0].reason == "Uso sospechoso detectado"
        assert updated.moderation_notes[0].created_by == "sysadmin"

    def test_multiple_notes_accumulate(self, store: AccountStore) -> None:
        account = asyncio.run(store.create_from_request(_request(), password_hash="hash1"))

        asyncio.run(
            store.add_moderation_note(account.id, kind=ModerationNoteKind.WARNING, reason="r1", created_by="sysadmin")
        )
        updated = asyncio.run(
            store.add_moderation_note(account.id, kind=ModerationNoteKind.REPORT, reason="r2", created_by="sysadmin")
        )

        assert len(updated.moderation_notes) == 2
        assert updated.moderation_notes[1].kind == ModerationNoteKind.REPORT


class TestAccountEncryptionAtRest:
    def test_full_name_is_encrypted_on_disk_when_encryptor_configured(self, tmp_path: Path) -> None:
        encryption = get_encryption_service(_random_master_key())
        encryptor = SensitiveFieldEncryptor(encryption)
        path = tmp_path / "accounts.jsonl"
        store = AccountStore(store_path=path, encryptor=encryptor)

        asyncio.run(store.create_from_request(_request(full_name="Nombre Confidencial"), password_hash="hash1"))

        raw_content = path.read_text(encoding="utf-8")
        assert "Nombre Confidencial" not in raw_content

    def test_password_hash_is_never_encrypted_wrapped(self, tmp_path: Path) -> None:
        """El password_hash ya es irreversible (scrypt) — se persiste tal cual, sin envoltura AES."""
        encryption = get_encryption_service(_random_master_key())
        encryptor = SensitiveFieldEncryptor(encryption)
        path = tmp_path / "accounts.jsonl"
        store = AccountStore(store_path=path, encryptor=encryptor)

        asyncio.run(store.create_from_request(_request(), password_hash="scrypt$abc$def"))

        raw_content = path.read_text(encoding="utf-8")
        assert "scrypt$abc$def" in raw_content

    def test_account_is_decrypted_when_read_back(self, tmp_path: Path) -> None:
        encryption = get_encryption_service(_random_master_key())
        encryptor = SensitiveFieldEncryptor(encryption)
        path = tmp_path / "accounts.jsonl"
        store = AccountStore(store_path=path, encryptor=encryptor)

        asyncio.run(store.create_from_request(_request(full_name="Nombre Confidencial"), password_hash="hash1"))

        accounts = asyncio.run(store.list_all())

        assert accounts[0].full_name == "Nombre Confidencial"
