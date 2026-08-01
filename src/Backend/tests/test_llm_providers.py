"""Tests unitarios de la capa de proveedores LLM (HU-012).

Cumplen el DoD con red mockeada (`httpx.MockTransport`) y `MockLLMProvider`:
ninguna prueba requiere Gemini, Ollama ni clave de API reales.
"""

import asyncio
import json

import httpx
import pytest

from atrox.ai.providers.base import (
    LLMGenerationError,
    LLMResult,
    parse_json_text,
)
from atrox.ai.providers.fallback import FallbackLLMProvider
from atrox.ai.providers.gemini import GeminiProvider
from atrox.ai.providers.mock import MockLLMProvider
from atrox.ai.providers.ollama import OllamaProvider

SCHEMA = {
    "type": "object",
    "properties": {"analysis": {"type": "string"}},
    "required": ["analysis"],
}


def make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# -- parse_json_text (base) ---------------------------------------------------


class TestParseJsonText:
    def test_plain_json_object(self) -> None:
        assert parse_json_text('{"a": 1}') == {"a": 1}

    def test_tolerates_markdown_fences(self) -> None:
        assert parse_json_text('```json\n{"a": 1}\n```') == {"a": 1}

    def test_tolerates_fences_without_language(self) -> None:
        assert parse_json_text('```\n{"a": 1}\n```') == {"a": 1}

    def test_non_json_raises(self) -> None:
        with pytest.raises(LLMGenerationError):
            parse_json_text("esto no es json")

    def test_non_object_json_raises(self) -> None:
        with pytest.raises(LLMGenerationError):
            parse_json_text("[1, 2, 3]")


# -- MockLLMProvider -----------------------------------------------------------


class TestMockLLMProvider:
    def test_returns_preconfigured_content(self) -> None:
        provider = MockLLMProvider(content={"analysis": "SQLi crítico"})

        result = asyncio.run(provider.generate("analiza", SCHEMA))

        assert isinstance(result, LLMResult)
        assert result.provider == "mock"
        assert result.content == {"analysis": "SQLi crítico"}

    def test_default_echoes_prompt(self) -> None:
        provider = MockLLMProvider()

        result = asyncio.run(provider.generate("hola", SCHEMA))

        assert result.content["echo"] == "hola"

    def test_custom_model(self) -> None:
        provider = MockLLMProvider(model="mock-2")
        result = asyncio.run(provider.generate("x", SCHEMA))
        assert result.model == "mock-2"


# -- GeminiProvider (Cloud) ----------------------------------------------------


class TestGeminiProvider:
    def test_generate_parses_structured_json(self) -> None:
        client = make_client(
            lambda request: httpx.Response(
                200,
                json={
                    "candidates": [
                        {"content": {"parts": [{"text": '{"analysis": "SQLi"}'}]}}
                    ]
                },
            )
        )
        provider = GeminiProvider(api_key="test-key", http_client=client)

        result = asyncio.run(provider.generate("analiza esto", SCHEMA))

        assert result.provider == "gemini"
        assert result.content == {"analysis": "SQLi"}
        assert result.raw_text == '{"analysis": "SQLi"}'

    def test_generate_tolerates_markdown_fences(self) -> None:
        client = make_client(
            lambda request: httpx.Response(
                200,
                json={
                    "candidates": [
                        {"content": {"parts": [{"text": '```json\n{"analysis": "SQLi"}\n```'}]}}
                    ]
                },
            )
        )
        provider = GeminiProvider(api_key="test-key", http_client=client)

        result = asyncio.run(provider.generate("analiza esto", SCHEMA))

        assert result.content == {"analysis": "SQLi"}

    def test_http_error_raises(self) -> None:
        client = make_client(lambda request: httpx.Response(500, text="boom"))
        provider = GeminiProvider(api_key="test-key", http_client=client)

        with pytest.raises(LLMGenerationError, match="500"):
            asyncio.run(provider.generate("x", SCHEMA))

    def test_missing_api_key_raises(self) -> None:
        client = make_client(lambda request: httpx.Response(200, json={}))
        provider = GeminiProvider(api_key="", http_client=client)

        with pytest.raises(LLMGenerationError, match="ATROX_LLM_API_KEY"):
            asyncio.run(provider.generate("x", SCHEMA))

    def test_response_without_candidates_raises(self) -> None:
        client = make_client(lambda request: httpx.Response(200, json={}))
        provider = GeminiProvider(api_key="test-key", http_client=client)

        with pytest.raises(LLMGenerationError):
            asyncio.run(provider.generate("x", SCHEMA))

    def test_non_json_text_raises(self) -> None:
        client = make_client(
            lambda request: httpx.Response(
                200,
                json={"candidates": [{"content": {"parts": [{"text": "hola mundo"}]}}]},
            )
        )
        provider = GeminiProvider(api_key="test-key", http_client=client)

        with pytest.raises(LLMGenerationError):
            asyncio.run(provider.generate("x", SCHEMA))

    def test_network_error_raises(self) -> None:
        def handler(request):
            raise httpx.ConnectError("sin conexión")

        provider = GeminiProvider(api_key="test-key", http_client=make_client(handler))

        with pytest.raises(LLMGenerationError):
            asyncio.run(provider.generate("x", SCHEMA))


# -- OllamaProvider (local) ----------------------------------------------------


class TestOllamaProvider:
    def test_generate_parses_message_content(self) -> None:
        client = make_client(
            lambda request: httpx.Response(
                200,
                json={
                    "model": "llama3",
                    "message": {"role": "assistant", "content": '{"ok": true}'},
                    "done": True,
                },
            )
        )
        provider = OllamaProvider(model="llama3", http_client=client)

        result = asyncio.run(provider.generate("x", SCHEMA))

        assert result.provider == "ollama"
        assert result.content == {"ok": True}

    def test_request_payload(self) -> None:
        captured: dict = {}

        def handler(request):
            captured["body"] = json.loads(request.content)
            captured["url"] = str(request.url)
            return httpx.Response(200, json={"message": {"content": '{"ok": true}'}})

        provider = OllamaProvider(model="llama3", http_client=make_client(handler))

        asyncio.run(provider.generate("hola prompt", SCHEMA))

        body = captured["body"]
        assert captured["url"] == "http://localhost:11434/api/chat"
        assert body["model"] == "llama3"
        assert body["messages"][0]["role"] == "user"
        assert body["messages"][0]["content"] == "hola prompt"
        assert body["stream"] is False
        assert body["format"] == SCHEMA
        assert body["options"]["temperature"] == 0

    def test_http_error_raises(self) -> None:
        client = make_client(lambda request: httpx.Response(503, text="no"))
        provider = OllamaProvider(http_client=client)

        with pytest.raises(LLMGenerationError, match="503"):
            asyncio.run(provider.generate("x", SCHEMA))

    def test_network_error_raises(self) -> None:
        def handler(request):
            raise httpx.ConnectError("connection refused")

        provider = OllamaProvider(http_client=make_client(handler))

        with pytest.raises(LLMGenerationError):
            asyncio.run(provider.generate("x", SCHEMA))

    def test_missing_content_raises(self) -> None:
        client = make_client(lambda request: httpx.Response(200, json={"done": True}))
        provider = OllamaProvider(http_client=client)

        with pytest.raises(LLMGenerationError):
            asyncio.run(provider.generate("x", SCHEMA))

    def test_non_json_content_raises(self) -> None:
        client = make_client(
            lambda request: httpx.Response(200, json={"message": {"content": "no json"}})
        )
        provider = OllamaProvider(http_client=client)

        with pytest.raises(LLMGenerationError):
            asyncio.run(provider.generate("x", SCHEMA))


# -- FallbackLLMProvider -------------------------------------------------------


class FailingProvider:
    name = "failing"
    model = "fail-model"

    def __init__(self, error: Exception) -> None:
        self._error = error

    async def generate(self, prompt, schema):
        raise self._error


class TestFallbackLLMProvider:
    def test_backup_responds_when_primary_down(self) -> None:
        chain = FallbackLLMProvider(
            [
                FailingProvider(LLMGenerationError("gemini caído")),
                MockLLMProvider(content={"analysis": "fallback"}),
            ]
        )

        result = asyncio.run(chain.generate("x", SCHEMA))

        assert result.provider == "mock"
        assert result.content == {"analysis": "fallback"}

    def test_all_fail_propagates_error(self) -> None:
        chain = FallbackLLMProvider(
            [
                FailingProvider(LLMGenerationError("a")),
                FailingProvider(LLMGenerationError("b")),
            ]
        )

        with pytest.raises(LLMGenerationError):
            asyncio.run(chain.generate("x", SCHEMA))

    def test_empty_providers_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            FallbackLLMProvider([])

    def test_non_llm_error_propagates_immediately(self) -> None:
        chain = FallbackLLMProvider(
            [
                FailingProvider(RuntimeError("bug interno")),
                MockLLMProvider(content={"analysis": "x"}),
            ]
        )

        with pytest.raises(RuntimeError):
            asyncio.run(chain.generate("x", SCHEMA))
