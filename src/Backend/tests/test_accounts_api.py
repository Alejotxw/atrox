"""Tests de la API administrativa de cuentas de usuario (super admin)."""

import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from atrox.access_requests.models import AccessRequest
from atrox.accounts.store import AccountStore
from atrox.api.accounts import get_account_store
from atrox.main import app

ADMIN_HEADERS = {"Authorization": "Bearer test-audit-token"}


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


@pytest.fixture
def account_store(tmp_path: Path) -> AccountStore:
    return AccountStore(store_path=tmp_path / "accounts.jsonl")


@pytest.fixture
def client(account_store: AccountStore):
    app.dependency_overrides[get_account_store] = lambda: account_store
    yield TestClient(app)
    app.dependency_overrides.clear()


async def _seed_account(account_store: AccountStore, **overrides):
    return await account_store.create_from_request(_request(**overrides), password_hash="scrypt$x$y")


class TestListAccountsRequiresAdmin:
    def test_list_without_token_returns_401(self, client: TestClient) -> None:
        response = client.get("/api/accounts")
        assert response.status_code == 401

    def test_list_with_admin_token_returns_accounts(self, client: TestClient, account_store: AccountStore) -> None:

        asyncio.run(_seed_account(account_store))

        response = client.get("/api/accounts", headers=ADMIN_HEADERS)

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 1
        assert body["accounts"][0]["username"] == "ana.torres"
        assert "password_hash" not in body["accounts"][0]


class TestSuspendReactivateDelete:
    def test_suspend_sets_status(self, client: TestClient, account_store: AccountStore) -> None:

        account = asyncio.run(_seed_account(account_store))

        response = client.post(f"/api/accounts/{account.id}/suspend", headers=ADMIN_HEADERS)

        assert response.status_code == 200
        assert response.json()["status"] == "suspended"

    def test_reactivate_sets_status_active(self, client: TestClient, account_store: AccountStore) -> None:

        account = asyncio.run(_seed_account(account_store))
        client.post(f"/api/accounts/{account.id}/suspend", headers=ADMIN_HEADERS)

        response = client.post(f"/api/accounts/{account.id}/reactivate", headers=ADMIN_HEADERS)

        assert response.status_code == 200
        assert response.json()["status"] == "active"

    def test_delete_sets_status_deleted(self, client: TestClient, account_store: AccountStore) -> None:

        account = asyncio.run(_seed_account(account_store))

        response = client.delete(f"/api/accounts/{account.id}", headers=ADMIN_HEADERS)

        assert response.status_code == 200
        assert response.json()["status"] == "deleted"

    def test_suspend_unknown_account_returns_404(self, client: TestClient) -> None:
        response = client.post(
            "/api/accounts/00000000-0000-0000-0000-000000000000/suspend", headers=ADMIN_HEADERS
        )
        assert response.status_code == 404

    def test_actions_without_admin_token_return_401(self, client: TestClient, account_store: AccountStore) -> None:

        account = asyncio.run(_seed_account(account_store))

        assert client.post(f"/api/accounts/{account.id}/suspend").status_code == 401
        assert client.delete(f"/api/accounts/{account.id}").status_code == 401


class TestModerationNotes:
    def test_warn_account_appends_note(self, client: TestClient, account_store: AccountStore) -> None:

        account = asyncio.run(_seed_account(account_store))

        response = client.post(
            f"/api/accounts/{account.id}/warnings",
            json={"reason": "Uso sospechoso de credenciales compartidas"},
            headers=ADMIN_HEADERS,
        )

        assert response.status_code == 201
        body = response.json()
        assert len(body["moderation_notes"]) == 1
        assert body["moderation_notes"][0]["kind"] == "warning"
        assert body["moderation_notes"][0]["reason"] == "Uso sospechoso de credenciales compartidas"

    def test_report_account_appends_note(self, client: TestClient, account_store: AccountStore) -> None:

        account = asyncio.run(_seed_account(account_store))

        response = client.post(
            f"/api/accounts/{account.id}/reports",
            json={"reason": "Escaneo fuera del alcance autorizado"},
            headers=ADMIN_HEADERS,
        )

        assert response.status_code == 201
        assert response.json()["moderation_notes"][0]["kind"] == "report"

    def test_moderation_note_reason_too_short_returns_422(
        self, client: TestClient, account_store: AccountStore
    ) -> None:

        account = asyncio.run(_seed_account(account_store))

        response = client.post(
            f"/api/accounts/{account.id}/warnings", json={"reason": "x"}, headers=ADMIN_HEADERS
        )

        assert response.status_code == 422
