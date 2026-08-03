"""Test de contrato OpenAPI para /api/ai/validate (HU-017 — DoD)."""

from fastapi.testclient import TestClient

from atrox.main import app


def _openapi_schema() -> dict:
    return TestClient(app).get("/openapi.json").json()


class TestValidateOpenApiContract:
    def test_validate_path_documented(self) -> None:
        schema = _openapi_schema()

        assert "/api/ai/validate" in schema["paths"]
        assert "post" in schema["paths"]["/api/ai/validate"]

    def test_request_schema_requires_kind_and_raw(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/ai/validate"]["post"]

        request_ref = post_op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        request_schema = schema["components"]["schemas"][request_ref.split("/")[-1]]

        assert set(request_schema["required"]) >= {"kind", "raw"}
        assert "kind" in request_schema["properties"]
        assert "raw" in request_schema["properties"]

    def test_response_schema_includes_validation_envelope(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/ai/validate"]["post"]

        response_ref = post_op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        response_schema = schema["components"]["schemas"][response_ref.split("/")[-1]]

        assert set(response_schema["properties"]) >= {
            "valid",
            "kind",
            "data",
            "error",
            "detail",
            "rejection_id",
        }

    def test_response_documents_422_validation_error(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/ai/validate"]["post"]

        assert "422" in post_op["responses"]
