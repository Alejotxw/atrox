"""Tests de la fábrica de proveedores LLM y su configuración (HU-012)."""

import pytest

from atrox.ai.providers.factory import build_llm_provider, build_single_provider
from atrox.ai.providers.fallback import FallbackLLMProvider
from atrox.ai.providers.gemini import GeminiProvider
from atrox.ai.providers.mock import MockLLMProvider
from atrox.ai.providers.ollama import OllamaProvider
from atrox.config import Settings


def make_settings(**overrides) -> Settings:
    return Settings(**overrides, _env_file=None)


class TestBuildSingleProvider:
    def test_mock(self) -> None:
        provider = build_single_provider("mock", make_settings())
        assert isinstance(provider, MockLLMProvider)

    def test_gemini(self) -> None:
        provider = build_single_provider("gemini", make_settings(llm_api_key="k"))
        assert isinstance(provider, GeminiProvider)
        assert provider.model == "gemini-2.0-flash"

    def test_ollama(self) -> None:
        provider = build_single_provider("ollama", make_settings())
        assert isinstance(provider, OllamaProvider)
        assert provider.model == "llama3"
        assert provider.base_url == "http://localhost:11434"

    def test_generic_model_override(self) -> None:
        provider = build_single_provider("ollama", make_settings(llm_model="qwen2"))
        assert provider.model == "qwen2"

    def test_unknown_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Desconocido"):
            build_single_provider("unknown", make_settings())


class TestBuildLLMProvider:
    def test_default_mock_without_fallback(self) -> None:
        provider = build_llm_provider(make_settings())
        assert isinstance(provider, MockLLMProvider)

    def test_gemini_with_ollama_fallback_builds_chain(self) -> None:
        provider = build_llm_provider(
            make_settings(
                llm_provider="gemini",
                llm_api_key="k",
                llm_fallback_providers=["ollama"],
            )
        )
        assert isinstance(provider, FallbackLLMProvider)
        assert provider.name == "gemini+ollama"

    def test_duplicate_and_mock_fallback_omitted(self) -> None:
        provider = build_llm_provider(
            make_settings(
                llm_provider="gemini",
                llm_api_key="k",
                llm_fallback_providers=["gemini", "mock", "ollama"],
            )
        )
        assert isinstance(provider, FallbackLLMProvider)
        assert provider.name == "gemini+ollama"

    def test_mock_ignores_fallback(self) -> None:
        provider = build_llm_provider(
            make_settings(llm_provider="mock", llm_fallback_providers=["ollama"])
        )
        assert isinstance(provider, MockLLMProvider)

    def test_unknown_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Desconocido"):
            build_llm_provider(make_settings(llm_provider="unknown"))

    def test_ollama_primary_single_when_no_fallback(self) -> None:
        provider = build_llm_provider(make_settings(llm_provider="ollama"))
        assert isinstance(provider, OllamaProvider)


class TestLlmSettings:
    def test_defaults(self) -> None:
        settings = make_settings()
        assert settings.llm_provider == "mock"
        assert settings.llm_model is None
        assert settings.llm_timeout_seconds == 30
        assert settings.llm_gemini_model == "gemini-2.0-flash"
        assert settings.llm_ollama_base_url == "http://localhost:11434"
        assert settings.llm_ollama_model == "llama3"
        assert settings.llm_fallback_providers == []

    def test_env_override(self, monkeypatch) -> None:
        monkeypatch.setenv("ATROX_LLM_PROVIDER", "ollama")
        settings = Settings(_env_file=None)
        assert settings.llm_provider == "ollama"

    def test_fallback_list_from_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ATROX_LLM_FALLBACK_PROVIDERS", '["gemini", "ollama"]')
        settings = Settings(_env_file=None)
        assert settings.llm_fallback_providers == ["gemini", "ollama"]
