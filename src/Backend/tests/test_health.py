import time

from fastapi.testclient import TestClient

from atrox.main import app


def test_health_returns_200() -> None:
    client = TestClient(app)
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "service" in body
    assert "environment" in body


def test_health_responds_under_500ms() -> None:
    client = TestClient(app)

    start = time.perf_counter()
    response = client.get("/health")
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert response.status_code == 200
    assert elapsed_ms < 500, f"Healthcheck tardó {elapsed_ms:.2f} ms (límite: 500 ms)"


def test_settings_loaded_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("ATROX_APP_NAME", "Atrox Test")
    monkeypatch.setenv("ATROX_ENV", "testing")

    from atrox.config import get_settings

    get_settings.cache_clear()
    settings = get_settings()

    assert settings.app_name == "Atrox Test"
    assert settings.env == "testing"

    get_settings.cache_clear()
