"""Abstracción de proveedores LLM (HU-012 / ADR-005).

Contrato común `generate(prompt, schema)`, selección por configuración y
respaldo automático entre motores Cloud (Gemini) y locales (Ollama).
"""

from atrox.ai.providers.base import LLMGenerationError, LLMProvider, LLMResult, parse_json_text
from atrox.ai.providers.factory import build_llm_provider, build_single_provider
from atrox.ai.providers.fallback import FallbackLLMProvider
from atrox.ai.providers.gemini import GeminiProvider
from atrox.ai.providers.mock import MockLLMProvider
from atrox.ai.providers.ollama import OllamaProvider

__all__ = [
    "FallbackLLMProvider",
    "GeminiProvider",
    "LLMGenerationError",
    "LLMProvider",
    "LLMResult",
    "MockLLMProvider",
    "OllamaProvider",
    "build_llm_provider",
    "build_single_provider",
    "parse_json_text",
]
