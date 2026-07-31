"""Tests de contrato OpenAPI para /api/scans (HU-009 — DoD: contrato en CI)."""

from fastapi.testclient import TestClient

from atrox.main import app


def _openapi_schema() -> dict:
    return TestClient(app).get("/openapi.json").json()


class TestScansOpenApiContract:
    """Scenario: El contrato de /api/scans queda publicado en el schema OpenAPI."""

    def test_post_scans_path_documented(self) -> None:
        schema = _openapi_schema()

        assert "/api/scans" in schema["paths"]
        assert "post" in schema["paths"]["/api/scans"]

    def test_post_scans_request_schema_requires_target_and_scan_type(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/scans"]["post"]

        request_ref = post_op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        request_schema = schema["components"]["schemas"][request_ref.split("/")[-1]]

        assert "target" in request_schema["properties"]
        assert "scan_type" in request_schema["properties"]
        assert set(request_schema["required"]) >= {"target", "scan_type"}

    def test_post_scans_returns_202_with_scan_id_and_status_schema(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/scans"]["post"]

        assert "202" in post_op["responses"]
        response_ref = post_op["responses"]["202"]["content"]["application/json"]["schema"]["$ref"]
        response_schema = schema["components"]["schemas"][response_ref.split("/")[-1]]

        assert set(response_schema["properties"]) >= {"scan_id", "status"}

    def test_post_scans_documents_422_validation_error(self) -> None:
        schema = _openapi_schema()
        post_op = schema["paths"]["/api/scans"]["post"]

        assert "422" in post_op["responses"]
