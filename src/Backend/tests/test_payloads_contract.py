"""Test de contrato OpenAPI para /api/ai/payloads/generate (HU-015 — DoD)."""

from fastapi.testclient import TestClient

from atrox.main import app


def _openapi_schema() -> dict:
    return TestClient(app).get("/openapi.json").json()


class TestPayloadsOpenApiContract:
    def test_generate_path_documented(self) -> None:
        schema = _openapi_schema()

        assert "/api/ai/payloads/generate" in schema["paths"]
        assert "post" in schema["paths"]["/api/ai/payloads/generate"]

    def test_request_schema_requires_finding(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/ai/payloads/generate"]["post"]

        request_ref = post_op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        request_schema = schema["components"]["schemas"][request_ref.split("/")[-1]]

        assert "finding" in request_schema["properties"]
        assert "finding_id" in request_schema["properties"]
        assert "finding" in request_schema["required"]

    def test_response_schema_includes_finding_id_and_disclaimer(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/ai/payloads/generate"]["post"]

        response_ref = post_op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        response_schema = schema["components"]["schemas"][response_ref.split("/")[-1]]

        assert set(response_schema["properties"]) >= {
            "finding_id",
            "service",
            "category",
            "suggestions",
            "disclaimer",
            "generation_time_ms",
            "within_sla",
        }

    def test_response_documents_422_validation_error(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/ai/payloads/generate"]["post"]

        assert "422" in post_op["responses"]
