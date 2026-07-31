"""Tests unitarios para POST /api/ai/scoring/score (HU-016)."""

from fastapi.testclient import TestClient

from atrox.main import app

client = TestClient(app)


def _finding_payload(**overrides) -> dict:
    data = {
        "template_id": "cve-2021-41773",
        "name": "Apache Path Traversal",
        "severity": "critical",
        "host": "http://example.com",
        "matched_at": "http://example.com/traversal",
        "tags": ["cve", "rce"],
        "extracted_results": ["root:x:0:0:root:/root:/bin/bash"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        "description": "Path traversal confirmado.",
    }
    data.update(overrides)
    return data


class TestScoreFindingApi:
    """Scenario: Obtener score de confianza para un hallazgo (spec requirement)."""

    def test_score_returns_200_with_structured_result(self) -> None:
        response = client.post(
            "/api/ai/scoring/score", json={"finding": _finding_payload()}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["finding_id"] == "cve-2021-41773"
        assert isinstance(body["score"], int)
        assert 0 <= body["score"] <= 100
        assert isinstance(body["probable_fp"], bool)
        assert isinstance(body["explanation"], str) and body["explanation"]

    def test_weak_finding_is_marked_probable_fp(self) -> None:
        weak = _finding_payload(
            template_id="tech-detect",
            severity="info",
            tags=["tech", "fingerprint"],
            extracted_results=[],
            references=[],
            description="",
        )

        response = client.post("/api/ai/scoring/score", json={"finding": weak})

        assert response.status_code == 200
        assert response.json()["probable_fp"] is True

    def test_explicit_threshold_overrides_default(self) -> None:
        # score 95 (< 100): critical + evidencia + cve, sin referencias.
        response = client.post(
            "/api/ai/scoring/score",
            json={"finding": _finding_payload(references=[]), "threshold": 100},
        )

        body = response.json()
        assert body["threshold"] == 100
        assert body["probable_fp"] is True

    def test_explicit_finding_id_is_respected(self) -> None:
        response = client.post(
            "/api/ai/scoring/score",
            json={"finding": _finding_payload(), "finding_id": "finding-xyz"},
        )

        assert response.json()["finding_id"] == "finding-xyz"

    def test_missing_finding_returns_422(self) -> None:
        response = client.post("/api/ai/scoring/score", json={})

        assert response.status_code == 422

    def test_threshold_out_of_range_returns_422(self) -> None:
        response = client.post(
            "/api/ai/scoring/score",
            json={"finding": _finding_payload(), "threshold": 150},
        )

        assert response.status_code == 422
