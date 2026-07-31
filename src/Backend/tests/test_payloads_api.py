"""Tests unitarios para POST /api/ai/payloads/generate (HU-015)."""

from fastapi.testclient import TestClient

from atrox.main import app

client = TestClient(app)


def _finding_payload(**overrides) -> dict:
    data = {
        "template_id": "generic-sqli-detect",
        "name": "SQL Injection Detected",
        "severity": "high",
        "host": "http://example.com",
        "matched_at": "http://example.com/login?id=1",
        "tags": ["sqli", "injection"],
    }
    data.update(overrides)
    return data


class TestGeneratePayloadsApi:
    """Scenario: Generar payloads para un hallazgo (spec requirement)."""

    def test_generate_returns_200_with_structured_result(self) -> None:
        response = client.post(
            "/api/ai/payloads/generate", json={"finding": _finding_payload()}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["finding_id"] == "generic-sqli-detect"
        assert body["category"] == "sqli"
        assert isinstance(body["suggestions"], list)
        assert len(body["suggestions"]) > 0

    def test_generate_respects_explicit_finding_id(self) -> None:
        response = client.post(
            "/api/ai/payloads/generate",
            json={"finding": _finding_payload(), "finding_id": "finding-abc-123"},
        )

        assert response.status_code == 200
        assert response.json()["finding_id"] == "finding-abc-123"

    def test_response_includes_authorized_lab_only_disclaimer(self) -> None:
        response = client.post(
            "/api/ai/payloads/generate", json={"finding": _finding_payload()}
        )

        body = response.json()
        assert "disclaimer" in body
        assert "autorizad" in body["disclaimer"].lower()

    def test_response_includes_generation_time_and_sla_flag(self) -> None:
        response = client.post(
            "/api/ai/payloads/generate", json={"finding": _finding_payload()}
        )

        body = response.json()
        assert "generation_time_ms" in body
        assert body["within_sla"] is True

    def test_missing_required_finding_fields_returns_422(self) -> None:
        response = client.post(
            "/api/ai/payloads/generate", json={"finding": {"template_id": "x"}}
        )

        assert response.status_code == 422

    def test_missing_finding_returns_422(self) -> None:
        response = client.post("/api/ai/payloads/generate", json={})

        assert response.status_code == 422
