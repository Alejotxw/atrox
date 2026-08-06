"""Tests del chat de IA sobre hallazgos (Motor Ollama IA)."""

import asyncio
import json

import pytest

from atrox.ai.agents.chat.chat_agent import ask, build_prompt
from atrox.ai.providers.base import LLMGenerationError, LLMResult
from atrox.ai.schemas.errors import ValidationRetriesExhaustedError


class FakeProvider:
    name = "fake"

    def __init__(self, content: dict | None = None, raw_text: str | None = None, model: str = "fake-model"):
        self.model = model
        self._content = content
        self._raw_text = raw_text if raw_text is not None else json.dumps(content or {})

    async def generate(self, prompt: str, schema: dict) -> LLMResult:
        return LLMResult(
            provider=self.name, model=self.model, content=self._content or {}, raw_text=self._raw_text,
        )


class FailingProvider:
    name = "failing"
    model = "unreachable"

    async def generate(self, prompt: str, schema: dict) -> LLMResult:
        raise LLMGenerationError("Error de red al llamar a Ollama: connection refused")


class TestBuildPrompt:
    def test_includes_message_and_schema(self) -> None:
        prompt = build_prompt("¿Qué es una SQLi?", None)
        assert "¿Qué es una SQLi?" in prompt
        assert '"response"' in prompt

    def test_includes_context_when_provided(self) -> None:
        prompt = build_prompt("resume esto", "2 hallazgos críticos")
        assert "2 hallazgos críticos" in prompt

    def test_omits_context_block_when_none(self) -> None:
        prompt = build_prompt("hola", None)
        assert "Contexto del escaneo actual" not in prompt


class TestAsk:
    def test_returns_response_text_on_success(self) -> None:
        provider = FakeProvider(content={"response": "Una inyección SQL permite..."})

        result = asyncio.run(ask("¿Qué es una SQLi?", None, provider))

        assert result == "Una inyección SQL permite..."

    def test_raises_on_generation_error(self) -> None:
        with pytest.raises(LLMGenerationError):
            asyncio.run(ask("hola", None, FailingProvider()))

    def test_raises_on_malformed_json(self) -> None:
        provider = FakeProvider(raw_text="no soy JSON")

        with pytest.raises(ValidationRetriesExhaustedError):
            asyncio.run(ask("hola", None, provider, max_retries=0))
