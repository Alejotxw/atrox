"""Proveedor Mock determinista para tests y desarrollo sin red (HU-012).

Es el default de configuración (`ATROX_LLM_PROVIDER=mock`): permite ejecutar
la lógica de negocio y los tests del DoD sin depender de Gemini u Ollama.
"""

import json
from typing import Any

from atrox.ai.providers.base import LLMResult


class MockLLMProvider:
    """Devuelve contenido prefijado sin realizar llamadas de red."""

    name = "mock"

    def __init__(
        self,
        model: str = "mock-model",
        content: dict[str, Any] | None = None,
    ) -> None:
        self.model = model
        self._content = content

    async def generate(self, prompt: str, schema: dict[str, Any]) -> LLMResult:
        content = self._content if self._content is not None else {"echo": prompt[:500]}
        raw_text = json.dumps(content, ensure_ascii=False)
        return LLMResult(
            provider=self.name,
            model=self.model,
            content=content,
            raw_text=raw_text,
        )
