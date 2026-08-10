"""Tests de la API pública de solicitudes de acceso (landing page pre-login)."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from atrox.access_requests.store import AccessRequestStore
from atrox.api.access_requests import get_access_request_store
from atrox.main import app


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
def ar_store(tmp_path: Path) -> AccessRequestStore:
    return AccessRequestStore(store_path=tmp_path / "access_requests.jsonl")


@pytest.fixture
def client(ar_store: AccessRequestStore):
    app.dependency_overrides[get_access_request_store] = lambda: ar_store
    yield TestClient(app)
    app.dependency_overrides.clear()


class TestSubmitAccessRequest:
    def test_submit_returns_201_with_persisted_fields(self, client: TestClient) -> None:
        response = client.post("/api/access-requests", json=_payload())

        assert response.status_code == 201
        body = response.json()
        assert body["full_name"] == "Ana Torres"
        assert body["email"] == "ana.torres@uide.edu.ec"
        assert body["id"] is not None
        assert body["created_at"] is not None

    def test_submit_missing_required_field_returns_422(self, client: TestClient) -> None:
        payload = _payload()
        del payload["reason"]

        response = client.post("/api/access-requests", json=payload)

        assert response.status_code == 422

    def test_submit_invalid_email_returns_422(self, client: TestClient) -> None:
        response = client.post("/api/access-requests", json=_payload(email="not-an-email"))

        assert response.status_code == 422

    def test_submit_is_public_without_auth_header(self, client: TestClient) -> None:
        response = client.post("/api/access-requests", json=_payload())

        assert response.status_code == 201


class TestListAccessRequestsRequiresAdmin:
    def test_list_without_token_returns_401(self, client: TestClient) -> None:
        response = client.get("/api/access-requests")

        assert response.status_code == 401

    def test_list_with_admin_token_returns_submitted_requests(self, client: TestClient) -> None:
        client.post("/api/access-requests", json=_payload())

        response = client.get(
            "/api/access-requests", headers={"Authorization": "Bearer test-audit-token"}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 1
        assert body["requests"][0]["full_name"] == "Ana Torres"
