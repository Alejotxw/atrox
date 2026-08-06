"""Tests del validador estructurado de respuestas IA con Pydantic (HU-017).

DoD: respuestas válidas e inválidas (JSON malformado + esquema no cumplido),
reintento y error controlado, y log de rechazos para depuración.
"""

import asyncio
import json
from pathlib import Path

import pytest

from atrox.ai.agents.payloads.models import PayloadGenerationResult
from atrox.ai.agents.scoring.models import ConfidenceScoreResult
from atrox.ai.agents.vectors.models import VectorAnalysisResult
from atrox.ai.schemas.errors import (
    InvalidJSONError,
    SchemaRejectionError,
    UnknownOutputKindError,
    ValidationRetriesExhaustedError,
)
from atrox.ai.schemas.rejections import RAW_MAX_LEN, RejectionLogStore, RejectionLogger, RejectionRecord
from atrox.ai.schemas.registry import SUPPORTED_KINDS, get_output_model
from atrox.ai.schemas.validator import LLMResponseValidator, extract_json_object, validate_raw

VALID_SCORES = {
    "finding_id": "tech-detect-nginx",
    "score": 85,
    "threshold": 40,
    "probable_fp": False,
    "explanation": "CVE confirmado con evidencia extraída",
    "generation_time_ms": 1.5,
    "within_sla": True,
}

VALID_PAYLOADS = {
    "finding_id": "generic-sqli-detect",
    "service": "web (nginx + php)",
    "category": "sqli",
    "suggestions": [
        {
            "category": "sqli",
            "payload": "x' OR '1'='1",
            "description": "Bypass de autenticación por inyección OR",
        }
    ],
    "generation_time_ms": 0.8,
    "within_sla": True,
}

VALID_VECTORS = {
    "vectors": [
        {
            "rank": 1,
            "vector_id": "web-sqli-to-db:sqli-login-blind+mssql-default-login",
            "name": "SQLi web → acceso a base de datos",
            "severity_score": 8.5,
            "finding_ids": ["sqli-login-blind", "mssql-default-login"],
            "chain": ["Explotar inyección SQL", "Extraer credenciales", "Acceder a la BD"],
            "justification": "Correlación automática entre hallazgos del mismo host.",
            "estimated_impact": "Compromiso de confidencialidad de datos",
        }
    ],
    "total_findings": 2,
    "analysis_time_ms": 3.2,
    "within_sla": True,
}


# ── Registro de esquemas Pydantic (vectors, payloads, scores) ───────────────


def test_registry_exposes_registered_output_kinds() -> None:
    assert SUPPORTED_KINDS == {"vectors", "vector_narrative", "payloads", "scores", "chat"}
    assert get_output_model("scores") is ConfidenceScoreResult
    assert get_output_model("payloads") is PayloadGenerationResult
    assert get_output_model("vectors") is VectorAnalysisResult


def test_unknown_kind_raises_controlled_error() -> None:
    with pytest.raises(UnknownOutputKindError):
        get_output_model("bogus")


# ── Respuestas válidas ───────────────────────────────────────────────────────


def test_valid_json_in_code_fence_validates() -> None:
    raw = "```json\n" + json.dumps(VALID_SCORES) + "\n```"
    result = validate_raw(raw, ConfidenceScoreResult)
    assert isinstance(result, ConfidenceScoreResult)
    assert result.score == 85
    assert result.probable_fp is False


def test_valid_plain_json_validates() -> None:
    result = validate_raw(json.dumps(VALID_PAYLOADS), PayloadGenerationResult)
    assert result.finding_id == "generic-sqli-detect"
    assert result.suggestions[0].category == "sqli"


def test_valid_json_with_surrounding_prose_validates() -> None:
    raw = "Aquí está el análisis solicitado:\n" + json.dumps(VALID_VECTORS) + "\nFin del análisis."
    result = validate_raw(raw, VectorAnalysisResult)
    assert result.total_findings == 2
    assert result.vectors[0].severity_score == 8.5


@pytest.mark.parametrize(
    ("kind", "payload"),
    [
        ("scores", VALID_SCORES),
        ("payloads", VALID_PAYLOADS),
        ("vectors", VALID_VECTORS),
    ],
)
def test_all_kinds_validate_through_validator(kind: str, payload: dict) -> None:
    async def llm_invoke() -> str:
        return json.dumps(payload)

    result = asyncio.run(LLMResponseValidator().validate(llm_invoke, kind=kind))
    assert result is not None


# ── Respuestas inválidas ─────────────────────────────────────────────────────


def test_missing_required_field_is_rejected() -> None:
    missing_score = {k: v for k, v in VALID_SCORES.items() if k != "score"}
    with pytest.raises(SchemaRejectionError):
        validate_raw(json.dumps(missing_score), ConfidenceScoreResult)


def test_out_of_range_score_rejected() -> None:
    bad = {**VALID_SCORES, "score": 150}
    with pytest.raises(SchemaRejectionError):
        validate_raw(json.dumps(bad), ConfidenceScoreResult)


def test_wrong_type_rejected() -> None:
    bad = {**VALID_SCORES, "score": "alto"}
    with pytest.raises(SchemaRejectionError):
        validate_raw(json.dumps(bad), ConfidenceScoreResult)


def test_malformed_json_rejected() -> None:
    with pytest.raises(InvalidJSONError):
        validate_raw("{esto no es json", ConfidenceScoreResult)


def test_empty_response_rejected() -> None:
    with pytest.raises(InvalidJSONError):
        validate_raw("", ConfidenceScoreResult)


def test_prose_without_json_rejected() -> None:
    with pytest.raises(InvalidJSONError):
        validate_raw("El modelo solo respondió texto, sin JSON.", ConfidenceScoreResult)


def test_extract_json_object_supports_fences() -> None:
    assert json.loads(extract_json_object('```json\n{"a": 1}\n```')) == {"a": 1}


# ── Reintento y error controlado ─────────────────────────────────────────────


class TestRetryBehaviour:
    def test_retry_succeeds_after_invalid_first_response(self) -> None:
        calls: list[int] = []

        async def llm_invoke() -> str:
            calls.append(1)
            if len(calls) == 1:
                return "no es json"
            return json.dumps(VALID_SCORES)

        validator = LLMResponseValidator(max_retries=2)
        result = asyncio.run(validator.validate(llm_invoke, kind="scores"))

        assert result.score == 85
        assert len(calls) == 2
        assert len(asyncio.run(validator.rejection_logger.read_all())) == 1

    def test_retries_exhausted_raises_controlled_error(self) -> None:
        calls: list[int] = []

        async def llm_invoke() -> str:
            calls.append(1)
            return "{json siempre inválido"

        validator = LLMResponseValidator(max_retries=2)
        with pytest.raises(ValidationRetriesExhaustedError):
            asyncio.run(validator.validate(llm_invoke, kind="scores"))

        assert len(calls) == 3
        assert len(asyncio.run(validator.rejection_logger.read_all())) == 3

    def test_default_no_retry(self) -> None:
        calls: list[int] = []

        async def llm_invoke() -> str:
            calls.append(1)
            return "sin json"

        validator = LLMResponseValidator()
        with pytest.raises(ValidationRetriesExhaustedError):
            asyncio.run(validator.validate(llm_invoke, kind="scores"))

        assert len(calls) == 1

    def test_valid_first_response_no_rejections(self) -> None:
        calls: list[int] = []

        async def llm_invoke() -> str:
            calls.append(1)
            return json.dumps(VALID_SCORES)

        validator = LLMResponseValidator()
        result = asyncio.run(validator.validate(llm_invoke, kind="scores"))

        assert len(calls) == 1
        assert result.score == 85
        assert asyncio.run(validator.rejection_logger.read_all()) == []

    def test_unknown_kind_never_invokes_llm(self) -> None:
        calls: list[int] = []

        async def llm_invoke() -> str:
            calls.append(1)
            return "{}"

        validator = LLMResponseValidator()
        with pytest.raises(UnknownOutputKindError):
            asyncio.run(validator.validate(llm_invoke, kind="bogus"))

        assert calls == []


# ── Log de rechazos para depuración ──────────────────────────────────────────


def test_rejection_logger_in_memory_by_default() -> None:
    logger = RejectionLogger()
    asyncio.run(
        logger.record(
            kind="payloads", error="SchemaRejectionError", detail="falta field", raw="{}", attempt=1
        )
    )

    records = asyncio.run(logger.read_all())
    assert len(records) == 1
    assert records[0].kind == "payloads"
    assert records[0].attempt == 1


def test_rejection_persists_to_jsonl(tmp_path: Path) -> None:
    log_path = tmp_path / "rejections.jsonl"
    logger = RejectionLogger(store=RejectionLogStore(log_path))

    record = asyncio.run(
        logger.record(
            kind="scores", error="InvalidJSONError", detail="no se encontró JSON", raw="nope", attempt=1
        )
    )

    assert isinstance(record, RejectionRecord)
    assert record.error == "InvalidJSONError"

    entries = asyncio.run(RejectionLogStore(log_path).read_all())
    assert len(entries) == 1
    assert entries[0]["kind"] == "scores"
    assert entries[0]["attempt"] == 1
    assert entries[0]["id"] == record.id


def test_rejection_raw_truncated_for_debugging(tmp_path: Path) -> None:
    logger = RejectionLogger(store=RejectionLogStore(tmp_path / "rejections.jsonl"))
    huge = "x" * (RAW_MAX_LEN * 2)

    record = asyncio.run(
        logger.record(kind="vectors", error="InvalidJSONError", detail="d", raw=huge, attempt=1)
    )

    assert len(record.raw) == RAW_MAX_LEN
    assert record.raw == "x" * RAW_MAX_LEN
