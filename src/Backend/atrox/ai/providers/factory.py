"""Fábrica de proveedores LLM por configuración (HU-012 / ADR-005).

`ATROX_LLM_PROVIDER` selecciona el motor primario y
`ATROX_LLM_FALLBACK_PROVIDERS` define el orden de respaldo (lista JSON).
La lógica de negocio siempre recibe el mismo contrato `LLMProvider.generate`;
cambiar de motor es solo configuración, sin tocar código.
"""

from atrox.ai.providers.base import LLMProvider
from atrox.ai.providers.fallback import FallbackLLMProvider
from atrox.ai.providers.gemini import GeminiProvider
from atrox.ai.providers.mock import MockLLMProvider
from atrox.ai.providers.ollama import OllamaProvider
from atrox.config import Settings

PROVIDER_NAMES = ("gemini", "ollama", "mock")


def build_single_provider(name: str, settings: Settings) -> LLMProvider:
    """Construye un proveedor individual por nombre y configuración."""
    if name == "gemini":
        return GeminiProvider(
            api_key=settings.llm_api_key,
            model=settings.llm_model or settings.llm_gemini_model,
            timeout_seconds=settings.llm_timeout_seconds,
        )
    if name == "ollama":
        return OllamaProvider(
            model=settings.llm_model or settings.llm_ollama_model,
            base_url=settings.llm_ollama_base_url,
            timeout_seconds=settings.llm_timeout_seconds,
            num_predict=settings.llm_ollama_num_predict,
            num_ctx=settings.llm_ollama_num_ctx,
            keep_alive=settings.llm_ollama_keep_alive,
        )
    if name == "mock":
        return MockLLMProvider(model=settings.llm_model or "mock-model")

    raise ValueError(
        f"Proveedor LLM desconocido: {name!r}. Válidos: {', '.join(PROVIDER_NAMES)}"
    )


def build_llm_provider(settings: Settings) -> LLMProvider:
    """Arma la cadena primario + respaldos según la configuración.

    El proveedor `mock` se omite como respaldo para no ocultar fallos reales
    de los motores Cloud/local.
    """
    primary_name = settings.llm_provider
    chain: list[LLMProvider] = [build_single_provider(primary_name, settings)]

    if primary_name != "mock":
        for fallback_name in settings.llm_fallback_providers:
            if fallback_name == primary_name or fallback_name == "mock":
                continue
            chain.append(build_single_provider(fallback_name, settings))

    if len(chain) == 1:
        return chain[0]
    return FallbackLLMProvider(chain)
