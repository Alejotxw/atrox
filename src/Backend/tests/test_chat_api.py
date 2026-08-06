"""Tests del endpoint POST /api/ai/chat (Motor Ollama IA)."""

import json

from fastapi.testclient import TestClient

from atrox.ai.providers.base import LLMGenerationError, LLMResult
from atrox.config import Settings
from atrox.main import app

client = TestClient(app)


class FakeProvider:
    name = "fake"
    model = "qwen2.5:3b"

    def __init__(self, content: dict | None = None):
        self._content = content or {}

    async def generate(self, prompt: str, schema: dict) -> LLMResult:
        return LLMResult(
            provider=self.name,
            model=self.model,
            content=self._content,
            raw_text=json.dumps(self._content),
        )


class FailingProvider:
    name = "failing"
    model = "unreachable"

    async def generate(self, prompt: str, schema: dict) -> LLMResult:
        raise LLMGenerationError("Ollama no responde")


class TestChatApi:
    def test_returns_503_when_llm_not_configured(self, monkeypatch) -> None:
        monkeypatch.setattr("atrox.api.chat.get_settings", lambda: Settings(_env_file=None))

        response = client.post("/api/ai/chat", json={"message": "hola"})

        assert response.status_code == 503
        assert "ATROX_LLM_PROVIDER" in response.json()["detail"]

    def test_returns_response_when_llm_configured(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "atrox.api.chat.get_settings",
            lambda: Settings(llm_provider="ollama", _env_file=None),
        )
        monkeypatch.setattr(
            "atrox.api.chat.build_llm_provider",
            lambda settings: FakeProvider(content={"response": "Una SQLi permite manipular consultas."}),
        )

        response = client.post(
            "/api/ai/chat", json={"message": "¿Qué es una SQLi?", "context": "1 hallazgo crítico"}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["response"] == "Una SQLi permite manipular consultas."
        assert body["model_used"] == "qwen2.5:3b"

    def test_returns_502_when_provider_fails(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "atrox.api.chat.get_settings",
            lambda: Settings(llm_provider="ollama", _env_file=None),
        )
        monkeypatch.setattr("atrox.api.chat.build_llm_provider", lambda settings: FailingProvider())

        response = client.post("/api/ai/chat", json={"message": "hola"})

        assert response.status_code == 502

    def test_rejects_empty_message(self) -> None:
        response = client.post("/api/ai/chat", json={"message": ""})
        assert response.status_code == 422
