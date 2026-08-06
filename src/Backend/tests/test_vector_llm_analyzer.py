"""Tests del análisis real de vectores vía LLM (HU-014 + HU-012/ADR-002)."""

import asyncio
import json

import pytest

from atrox.ai.agents.vectors.analyzer import VectorAnalysisAgent
from atrox.ai.agents.vectors.llm_analyzer import analyze_with_llm, build_prompt
from atrox.ai.providers.base import LLMGenerationError, LLMResult
from atrox.ai.schemas.errors import ValidationRetriesExhaustedError
from atrox.scanner.models import VulnFinding, VulnSeverity

SQL_INJECTION = VulnFinding(
    template_id="sqli-login-blind",
    name="SQL Injection (Blind)",
    severity=VulnSeverity.CRITICAL,
    host="http://lab.local",
    matched_at="http://lab.local/login.php?user=admin",
    tags=["sqli", "injection", "web"],
    description="Blind SQL injection in login form parameter 'user'",
    ip="192.168.1.10",
)

VALID_VECTOR_JSON = {
    "vectors": [
        {
            "rank": 1,
            "vector_id": "sqli-login-to-db",
            "name": "SQLi ciega en login",
            "severity_score": 9.5,
            "finding_ids": ["sqli-login-blind"],
            "chain": [
                "Explotar la inyección SQL ciega en el parámetro 'user'",
                "Extraer credenciales de la base de datos vía respuestas booleanas",
            ],
            "justification": "Un atacante puede extraer credenciales de administrador sin autenticarse.",
            "estimated_impact": "Acceso completo a la base de datos de usuarios",
        }
    ]
}


class FakeProvider:
    """Proveedor LLM falso para tests — implementa el contrato LLMProvider."""

    name = "fake"

    def __init__(self, content: dict | None = None, raw_text: str | None = None, model: str = "fake-model"):
        self.model = model
        self._content = content
        self._raw_text = raw_text if raw_text is not None else json.dumps(content or {})
        self.calls = 0

    async def generate(self, prompt: str, schema: dict) -> LLMResult:
        self.calls += 1
        return LLMResult(
            provider=self.name,
            model=self.model,
            content=self._content or {},
            raw_text=self._raw_text,
        )


class FailingProvider:
    """Proveedor LLM que siempre falla (simula Ollama caído/no configurado)."""

    name = "failing"
    model = "unreachable"

    async def generate(self, prompt: str, schema: dict) -> LLMResult:
        raise LLMGenerationError("Error de red al llamar a Ollama: connection refused")


class TestBuildPrompt:
    def test_prompt_includes_finding_details_and_schema(self) -> None:
        prompt = build_prompt([SQL_INJECTION])

        assert "sqli-login-blind" in prompt
        assert "SQL Injection (Blind)" in prompt
        assert "192.168.1.10" in prompt
        assert '"vectors"' in prompt  # esquema JSON incluido
        assert "atacante" in prompt.lower()


class TestAnalyzeWithLLM:
    def test_returns_vectors_on_valid_response(self) -> None:
        provider = FakeProvider(content=VALID_VECTOR_JSON)

        vectors = asyncio.run(analyze_with_llm([SQL_INJECTION], provider))

        assert len(vectors) == 1
        assert vectors[0].vector_id == "sqli-login-to-db"
        assert "credenciales de administrador" in vectors[0].justification

    def test_raises_on_generation_error(self) -> None:
        provider = FailingProvider()

        with pytest.raises(LLMGenerationError):
            asyncio.run(analyze_with_llm([SQL_INJECTION], provider))

    def test_raises_validation_retries_exhausted_on_malformed_json(self) -> None:
        provider = FakeProvider(raw_text="esto no es JSON en absoluto")

        with pytest.raises(ValidationRetriesExhaustedError):
            asyncio.run(analyze_with_llm([SQL_INJECTION], provider, max_retries=0))

    def test_raises_validation_retries_exhausted_on_schema_mismatch(self) -> None:
        provider = FakeProvider(content={"wrong_key": []})

        with pytest.raises(ValidationRetriesExhaustedError):
            asyncio.run(analyze_with_llm([SQL_INJECTION], provider, max_retries=0))


class TestVectorAnalysisAgentWithLLM:
    def test_uses_llm_result_when_provider_succeeds(self) -> None:
        provider = FakeProvider(content=VALID_VECTOR_JSON, model="qwen2.5:3b")
        agent = VectorAnalysisAgent(llm_provider=provider)

        result = asyncio.run(agent.analyze_async([SQL_INJECTION]))

        assert result.source == "llm"
        assert result.model_used == "qwen2.5:3b"
        assert len(result.vectors) == 1
        assert result.vectors[0].vector_id == "sqli-login-to-db"

    def test_falls_back_to_heuristic_when_llm_unreachable(self) -> None:
        agent = VectorAnalysisAgent(llm_provider=FailingProvider())

        result = asyncio.run(agent.analyze_async([SQL_INJECTION]))

        assert result.source == "heuristic"
        assert result.model_used is None
        assert len(result.vectors) >= 1

    def test_falls_back_to_heuristic_when_llm_output_invalid(self) -> None:
        agent = VectorAnalysisAgent(llm_provider=FakeProvider(raw_text="not json"))

        result = asyncio.run(agent.analyze_async([SQL_INJECTION]))

        assert result.source == "heuristic"

    def test_uses_heuristic_directly_when_no_provider_configured(self) -> None:
        agent = VectorAnalysisAgent(llm_provider=None)

        result = asyncio.run(agent.analyze_async([SQL_INJECTION]))

        assert result.source == "heuristic"

    def test_empty_findings_skips_llm_and_returns_empty(self) -> None:
        provider = FakeProvider(content=VALID_VECTOR_JSON)
        agent = VectorAnalysisAgent(llm_provider=provider)

        result = asyncio.run(agent.analyze_async([]))

        assert result.vectors == []
        assert provider.calls == 0
