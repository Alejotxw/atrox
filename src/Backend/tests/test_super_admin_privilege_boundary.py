"""Tests del límite de privilegio super-admin vs. cuentas regulares.

Cubre dos hallazgos de una revisión de seguridad:
1. Una cuenta regular (login sin TOTP) NO debe poder usar los endpoints de
   gestión de solicitudes/cuentas — antes bastaba con cualquier sesión
   válida porque `require_mfa_admin` no distinguía el dueño de la sesión.
2. Suspender/eliminar una cuenta debe revocar cualquier sesión ya activa de
   esa cuenta de inmediato, no dejarla vigente hasta que expire por tiempo.
"""

import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from atrox.access_requests.models import AccessRequest
from atrox.accounts.store import AccountStore
from atrox.api.accounts import get_account_store
from atrox.main import app
from atrox.security.mfa_service import MfaService, generate_totp_secret
from atrox.security.password_hasher import hash_password

ADMIN_HEADERS = {"Authorization": "Bearer test-audit-token"}
REGULAR_PASSWORD = "TempPass123!"


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
    app.state.mfa_service = MfaService(
        admin_username="sysadmin",
        admin_password="AtroxAdmin2026!",
        totp_secret=generate_totp_secret(),
        session_ttl_minutes=60,
        max_failed_attempts=5,
        lockout_minutes=15,
    )
    app.dependency_overrides[get_account_store] = lambda: account_store
    yield TestClient(app)
    app.dependency_overrides.clear()


def _regular_session_headers(client: TestClient, account_store: AccountStore) -> dict:
    account = asyncio.run(
        account_store.create_from_request(_request(), password_hash=hash_password(REGULAR_PASSWORD))
    )
    login_res = client.post(
        "/api/auth/login", json={"username": account.username, "password": REGULAR_PASSWORD}
    )
    assert login_res.status_code == 200
    token = login_res.json()["session_token"]
    return {"Authorization": f"Bearer {token}"}, account


class TestRegularAccountCannotManageOtherAccounts:
    def test_list_accounts_returns_403(self, client: TestClient, account_store: AccountStore) -> None:
        headers, _ = _regular_session_headers(client, account_store)

        response = client.get("/api/accounts", headers=headers)

        assert response.status_code == 403

    def test_suspend_account_returns_403(self, client: TestClient, account_store: AccountStore) -> None:
        headers, target = _regular_session_headers(client, account_store)

        response = client.post(f"/api/accounts/{target.id}/suspend", headers=headers)

        assert response.status_code == 403

    def test_delete_account_returns_403(self, client: TestClient, account_store: AccountStore) -> None:
        headers, target = _regular_session_headers(client, account_store)

        response = client.delete(f"/api/accounts/{target.id}", headers=headers)

        assert response.status_code == 403

    def test_warn_account_returns_403(self, client: TestClient, account_store: AccountStore) -> None:
        headers, target = _regular_session_headers(client, account_store)

        response = client.post(
            f"/api/accounts/{target.id}/warnings", json={"reason": "algo"}, headers=headers
        )

        assert response.status_code == 403

    def test_list_access_requests_returns_403(self, client: TestClient, account_store: AccountStore) -> None:
        headers, _ = _regular_session_headers(client, account_store)

        response = client.get("/api/access-requests", headers=headers)

        assert response.status_code == 403

    def test_approve_access_request_returns_403(self, client: TestClient, account_store: AccountStore) -> None:
        headers, _ = _regular_session_headers(client, account_store)
        submit_res = client.post(
            "/api/access-requests",
            json={
                "full_name": "Otro Solicitante",
                "email": "otro@uide.edu.ec",
                "organization": "UIDE",
                "role": "Estudiante",
                "reason": "Motivo de prueba con longitud suficiente.",
            },
        )
        request_id = submit_res.json()["id"]

        response = client.post(f"/api/access-requests/{request_id}/approve", headers=headers)

        assert response.status_code == 403

    def test_sysadmin_session_is_unaffected(self, client: TestClient, account_store: AccountStore) -> None:
        """Control: el sysadmin real sigue pudiendo usar estos endpoints."""
        response = client.get("/api/accounts", headers=ADMIN_HEADERS)
        assert response.status_code == 200


class TestSuspendRevokesActiveSession:
    def test_suspended_account_session_stops_working_immediately(
        self, client: TestClient, account_store: AccountStore
    ) -> None:
        headers, target = _regular_session_headers(client, account_store)

        # La sesión funciona antes de suspender
        assert client.get("/api/auth/me", headers=headers).status_code == 200

        suspend_res = client.post(f"/api/accounts/{target.id}/suspend", headers=ADMIN_HEADERS)
        assert suspend_res.status_code == 200

        # La MISMA sesión, ya emitida, deja de funcionar de inmediato
        response = client.get("/api/auth/me", headers=headers)
        assert response.status_code == 401

    def test_deleted_account_session_stops_working_immediately(
        self, client: TestClient, account_store: AccountStore
    ) -> None:
        headers, target = _regular_session_headers(client, account_store)

        assert client.get("/api/auth/me", headers=headers).status_code == 200

        delete_res = client.delete(f"/api/accounts/{target.id}", headers=ADMIN_HEADERS)
        assert delete_res.status_code == 200

        response = client.get("/api/auth/me", headers=headers)
        assert response.status_code == 401
