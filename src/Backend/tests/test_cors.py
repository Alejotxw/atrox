"""Tests de configuración CORS — necesario para que el frontend (otro origen) hable con la API."""

from fastapi.testclient import TestClient

from atrox.main import app

client = TestClient(app)


def test_preflight_allows_configured_frontend_origin() -> None:
    response = client.options(
        "/api/scans",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_preflight_rejects_unlisted_origin() -> None:
    response = client.options(
        "/api/scans",
        headers={
            "Origin": "http://evil.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert "access-control-allow-origin" not in response.headers


def test_actual_request_includes_cors_header_for_allowed_origin() -> None:
    response = client.get("/health", headers={"Origin": "http://localhost:5173"})

    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
