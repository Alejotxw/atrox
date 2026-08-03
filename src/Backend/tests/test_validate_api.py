"""Tests unitarios para POST /api/ai/validate (HU-017)."""

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from atrox.ai.schemas.rejections import RejectionLogger
from atrox.main import app

client = TestClient(app)

VALID_SCORES = {
    "finding_id": "tech-detect-nginx",
    "score": 85,
    "threshold": 40,
    "probable_fp": False,
    "explanation": "CVE confirmado con evidencia extraída",
    "generation_time_ms": 1.5,
    "within_sla": True,
}

VALID_VECTORS = {
    "vectors": [
        {
            "rank": 1,
            "vector_id": "standalone:tech-detect",
            "name": "Explotación directa",
            "severity_score": 5.0,
            "finding_ids": ["tech-detect"],
            "chain": ["Identificar superficie", "Validar explotabilidad"],
            "justification": "Hallazgo de severidad media.",
            "estimated_impact": "Impacto proporcional",
        }
    ],
    "total_findings": 1,
    "analysis_time_ms": 2.0,
    "within_sla": True,
}


@pytest.fixture
def rejection_logger() -> RejectionLogger:
    logger = RejectionLogger()
    app.state.llm_rejections = logger
    return logger


def test_valid_scores_response_returns_200(rejection_logger: RejectionLogger) -> None:
    response = client.post(
        "/api/ai/validate", json={"kind": "scores", "raw": json.dumps(VALID_SCORES)}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["kind"] == "scores"
    assert body["data"]["score"] == 85
    assert body["error"] is None


def test_valid_vectors_response_returns_200(rejection_logger: RejectionLogger) -> None:
    response = client.post(
        "/api/ai/validate", json={"kind": "vectors", "raw": json.dumps(VALID_VECTORS)}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["data"]["total_findings"] == 1


def test_invalid_json_returns_422_and_logs_rejection(rejection_logger: RejectionLogger) -> None:
    response = client.post("/api/ai/validate", json={"kind": "scores", "raw": "{not json"})

    assert response.status_code == 422
    body = response.json()
    assert body["valid"] is False
    assert body["error"] == "InvalidJSONError"
    assert body["rejection_id"]

    records = asyncio.run(rejection_logger.read_all())
    assert len(records) == 1
    assert records[0].error == "InvalidJSONError"
    assert records[0].id == body["rejection_id"]


def test_schema_violation_returns_422(rejection_logger: RejectionLogger) -> None:
    missing_score = {k: v for k, v in VALID_SCORES.items() if k != "score"}
    response = client.post(
        "/api/ai/validate", json={"kind": "scores", "raw": json.dumps(missing_score)}
    )

    assert response.status_code == 422
    body = response.json()
    assert body["valid"] is False
    assert body["error"] == "SchemaRejectionError"


def test_unknown_kind_returns_422_without_rejection(rejection_logger: RejectionLogger) -> None:
    response = client.post("/api/ai/validate", json={"kind": "bogus", "raw": "{}"})

    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "UnknownOutputKindError"
    assert body["rejection_id"] is None

    assert asyncio.run(rejection_logger.read_all()) == []


def test_missing_request_fields_returns_422(rejection_logger: RejectionLogger) -> None:
    response = client.post("/api/ai/validate", json={"kind": "scores"})

    assert response.status_code == 422
