"""Tests del login de cuentas regulares (creadas al aprobar una solicitud), sin TOTP."""

import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from atrox.access_requests.models import AccessRequest
from atrox.accounts.models import AccountStatus
from atrox.accounts.store import AccountStore
from atrox.api.accounts import get_account_store
from atrox.main import app
from atrox.security.mfa_service import MfaService, generate_totp_secret
from atrox.security.password_hasher import hash_password


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
        max_failed_attempts=3,
        lockout_minutes=15,
    )
    app.dependency_overrides[get_account_store] = lambda: account_store
    yield TestClient(app)
    app.dependency_overrides.clear()


def _seed_active_account(account_store: AccountStore, password: str = "TempPass123!"):
    return asyncio.run(
        account_store.create_from_request(_request(), password_hash=hash_password(password))
    )


class TestRegularAccountLogin:
    def test_login_with_correct_password_skips_mfa(self, client: TestClient, account_store: AccountStore) -> None:
        account = _seed_active_account(account_store, password="TempPass123!")

        response = client.post(
            "/api/auth/login", json={"username": account.username, "password": "TempPass123!"}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["mfa_required"] is False
        assert "session_token" in body
        assert body["user"]["username"] == account.username

    def test_session_token_grants_access_to_protected_endpoints(
        self, client: TestClient, account_store: AccountStore
    ) -> None:
        account = _seed_active_account(account_store, password="TempPass123!")
        login_res = client.post(
            "/api/auth/login", json={"username": account.username, "password": "TempPass123!"}
        )
        session_token = login_res.json()["session_token"]

        me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {session_token}"})

        assert me_res.status_code == 200
        assert me_res.json()["username"] == account.username

    def test_login_with_wrong_password_returns_401(self, client: TestClient, account_store: AccountStore) -> None:
        account = _seed_active_account(account_store, password="TempPass123!")

        response = client.post(
            "/api/auth/login", json={"username": account.username, "password": "WrongPassword"}
        )

        assert response.status_code == 401

    def test_login_unknown_username_returns_401(self, client: TestClient) -> None:
        response = client.post("/api/auth/login", json={"username": "nadie", "password": "x"})
        assert response.status_code == 401

    def test_suspended_account_cannot_login(self, client: TestClient, account_store: AccountStore) -> None:
        account = _seed_active_account(account_store, password="TempPass123!")
        asyncio.run(account_store.set_status(account.id, AccountStatus.SUSPENDED))

        response = client.post(
            "/api/auth/login", json={"username": account.username, "password": "TempPass123!"}
        )

        assert response.status_code == 401

    def test_deleted_account_cannot_login(self, client: TestClient, account_store: AccountStore) -> None:
        account = _seed_active_account(account_store, password="TempPass123!")
        asyncio.run(account_store.set_status(account.id, AccountStatus.DELETED))

        response = client.post(
            "/api/auth/login", json={"username": account.username, "password": "TempPass123!"}
        )

        assert response.status_code == 401

    def test_repeated_failures_lock_out_regular_account(
        self, client: TestClient, account_store: AccountStore
    ) -> None:
        account = _seed_active_account(account_store, password="TempPass123!")

        for _ in range(3):
            client.post("/api/auth/login", json={"username": account.username, "password": "wrong"})

        response = client.post(
            "/api/auth/login", json={"username": account.username, "password": "TempPass123!"}
        )

        assert response.status_code == 429
