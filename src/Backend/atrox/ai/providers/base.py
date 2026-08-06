"""Capa de abstracción de proveedores LLM (HU-012).

Define el contrato único que la lógica de negocio usa para invocar un LLM:
`generate(prompt, schema)`. Los proveedores concretos (Gemini Cloud, Ollama
local, Mock) implementan este contrato y son intercambiables por configuración
vía `atrox.ai.providers.factory.build_llm_provider` — cambiar el motor de IA
no modifica la lógica de negocio (ADR-005 / ADR-002).
"""

import json
from typing import Any, Protocol

from pydantic import BaseModel


class LLMGenerationError(Exception):
    """El proveedor LLM no respondió, respondió con error o devolvió formato inválido."""


class LLMResult(BaseModel):
    """Resultado estructurado de una generación, ya parseado como objeto JSON."""

    provider: str
    model: str
    content: dict[str, Any]
    raw_text: str


class LLMProvider(Protocol):
    """Contrato común de los proveedores LLM.

    `schema` es un JSON Schema (dict) que el proveedor debe respetar; la
    implementación retorna `LLMResult.content` ya parseado. Cualquier fallo
    (red, HTTP, formato, clave ausente) se traduce a `LLMGenerationError`,
    que `FallbackLLMProvider` aprovecha para intentar el siguiente proveedor.
    """

    name: str
    model: str

    async def generate(self, prompt: str, schema: dict[str, Any]) -> LLMResult: ...


def parse_json_text(text: str) -> dict[str, Any]:
    """Parsea el texto devuelto por un LLM a un objeto JSON.

    Tolera fences markdown (```json ... ```) que algunos modelos agregan.
    Lanza `LLMGenerationError` si el texto no es JSON o no es un objeto.
    """
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`").strip()
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()

    try:
        data = json.loads(cleaned)
    except ValueError as exc:
        raise LLMGenerationError(
            "El texto devuelto por el LLM no es JSON válido"
        ) from exc

    if not isinstance(data, dict):
        raise LLMGenerationError("El JSON devuelto por el LLM no es un objeto")

    return data
