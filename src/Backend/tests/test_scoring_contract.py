"""Test de contrato OpenAPI para /api/ai/scoring/score (HU-016 — salida JSON validada por esquema)."""

from fastapi.testclient import TestClient

from atrox.main import app


def _openapi_schema() -> dict:
    return TestClient(app).get("/openapi.json").json()


class TestScoringOpenApiContract:
    def test_score_path_documented(self) -> None:
        schema = _openapi_schema()

        assert "/api/ai/scoring/score" in schema["paths"]
        assert "post" in schema["paths"]["/api/ai/scoring/score"]

    def test_request_schema_requires_finding(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/ai/scoring/score"]["post"]

        request_ref = post_op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        request_schema = schema["components"]["schemas"][request_ref.split("/")[-1]]

        assert "finding" in request_schema["required"]
        assert "threshold" in request_schema["properties"]

    def test_response_schema_includes_score_fields(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/ai/scoring/score"]["post"]

        response_ref = post_op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        response_schema = schema["components"]["schemas"][response_ref.split("/")[-1]]

        assert set(response_schema["properties"]) >= {
            "finding_id",
            "score",
            "threshold",
            "probable_fp",
            "explanation",
            "generation_time_ms",
            "within_sla",
        }

    def test_score_field_has_0_100_bounds_documented(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/ai/scoring/score"]["post"]
        response_ref = post_op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        response_schema = schema["components"]["schemas"][response_ref.split("/")[-1]]

        score_prop = response_schema["properties"]["score"]
        assert score_prop.get("minimum") == 0
        assert score_prop.get("maximum") == 100

    def test_response_documents_422_validation_error(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/ai/scoring/score"]["post"]

        assert "422" in post_op["responses"]
