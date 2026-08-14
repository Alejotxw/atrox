"""Tests de aprobación/rechazo de solicitudes de acceso (super admin)."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from atrox.access_requests.store import AccessRequestStore
from atrox.accounts.store import AccountStore
from atrox.api.access_requests import get_access_request_store
from atrox.api.accounts import get_account_store
from atrox.main import app
from atrox.security.password_hasher import verify_password

ADMIN_HEADERS = {"Authorization": "Bearer test-audit-token"}


def _payload(**overrides) -> dict:
    data = {
        "full_name": "Ana Torres",
        "email": "ana.torres@uide.edu.ec",
        "organization": "UIDE - Facultad de Ingeniería",
        "role": "Estudiante",
        "reason": "Necesito acceso para el proyecto de tesis sobre pentesting.",
    }
    data.update(overrides)
    return data


@pytest.fixture
def request_store(tmp_path: Path) -> AccessRequestStore:
    return AccessRequestStore(store_path=tmp_path / "access_requests.jsonl")


@pytest.fixture
def account_store(tmp_path: Path) -> AccountStore:
    return AccountStore(store_path=tmp_path / "accounts.jsonl")


@pytest.fixture
def client(request_store: AccessRequestStore, account_store: AccountStore):
    app.dependency_overrides[get_access_request_store] = lambda: request_store
    app.dependency_overrides[get_account_store] = lambda: account_store
    yield TestClient(app)
    app.dependency_overrides.clear()


def _submit(client: TestClient, **overrides) -> str:
    response = client.post("/api/access-requests", json=_payload(**overrides))
    return response.json()["id"]


class TestApprove:
    def test_approve_creates_account_and_returns_temporary_password_once(self, client: TestClient) -> None:
        request_id = _submit(client)

        response = client.post(f"/api/access-requests/{request_id}/approve", headers=ADMIN_HEADERS)

        assert response.status_code == 200
        body = response.json()
        assert body["account"]["username"] == "ana.torres"
        assert body["account"]["status"] == "active"
        assert len(body["temporary_password"]) >= 8
        assert "password_hash" not in body["account"]

    def test_approve_marks_request_as_approved(
        self, client: TestClient, request_store: AccessRequestStore
    ) -> None:
        import asyncio
        from uuid import UUID

        request_id = _submit(client)
        client.post(f"/api/access-requests/{request_id}/approve", headers=ADMIN_HEADERS)

        updated = asyncio.run(request_store.get(UUID(request_id)))

        assert updated.status.value == "approved"
        assert updated.account_id is not None

    def test_temporary_password_actually_works_for_login(
        self, client: TestClient, account_store: AccountStore
    ) -> None:
        import asyncio

        request_id = _submit(client)
        approve_response = client.post(f"/api/access-requests/{request_id}/approve", headers=ADMIN_HEADERS)
        temp_password = approve_response.json()["temporary_password"]
        username = approve_response.json()["account"]["username"]

        account = asyncio.run(account_store.get_by_username(username))

        assert verify_password(temp_password, account.password_hash) is True

    def test_approve_twice_returns_409(self, client: TestClient) -> None:
        request_id = _submit(client)
        client.post(f"/api/access-requests/{request_id}/approve", headers=ADMIN_HEADERS)

        second = client.post(f"/api/access-requests/{request_id}/approve", headers=ADMIN_HEADERS)

        assert second.status_code == 409

    def test_approve_unknown_request_returns_404(self, client: TestClient) -> None:
        response = client.post(
            "/api/access-requests/00000000-0000-0000-0000-000000000000/approve", headers=ADMIN_HEADERS
        )
        assert response.status_code == 404

    def test_approve_requires_admin(self, client: TestClient) -> None:
        request_id = _submit(client)

        response = client.post(f"/api/access-requests/{request_id}/approve")

        assert response.status_code == 401


class TestReject:
    def test_reject_marks_request_rejected_with_reason(self, client: TestClient) -> None:
        request_id = _submit(client)

        response = client.post(
            f"/api/access-requests/{request_id}/reject",
            json={"reason": "Correo institucional no verificable"},
            headers=ADMIN_HEADERS,
        )

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "rejected"
        assert body["review_reason"] == "Correo institucional no verificable"

    def test_reject_without_body_is_allowed(self, client: TestClient) -> None:
        request_id = _submit(client)

        response = client.post(f"/api/access-requests/{request_id}/reject", headers=ADMIN_HEADERS)

        assert response.status_code == 200
        assert response.json()["status"] == "rejected"

    def test_reject_with_json_content_type_and_empty_body_is_allowed(self, client: TestClient) -> None:
        """El frontend (fetch) siempre manda Content-Type: application/json, incluso sin
        `reason` — a diferencia de TestClient sin argumento `json=`, que no manda ese
        header. Confirma que FastAPI acepta ese caso real (body vacío, header presente)."""
        request_id = _submit(client)

        response = client.post(
            f"/api/access-requests/{request_id}/reject",
            headers={**ADMIN_HEADERS, "Content-Type": "application/json"},
            content=b"",
        )

        assert response.status_code == 200
        assert response.json()["status"] == "rejected"

    def test_reject_does_not_create_account(self, client: TestClient, account_store: AccountStore) -> None:
        import asyncio

        request_id = _submit(client)
        client.post(f"/api/access-requests/{request_id}/reject", headers=ADMIN_HEADERS)

        accounts = asyncio.run(account_store.list_all())

        assert accounts == []

    def test_reject_already_reviewed_returns_409(self, client: TestClient) -> None:
        request_id = _submit(client)
        client.post(f"/api/access-requests/{request_id}/reject", headers=ADMIN_HEADERS)

        second = client.post(f"/api/access-requests/{request_id}/reject", headers=ADMIN_HEADERS)

        assert second.status_code == 409

    def test_reject_requires_admin(self, client: TestClient) -> None:
        request_id = _submit(client)

        response = client.post(f"/api/access-requests/{request_id}/reject")

        assert response.status_code == 401
