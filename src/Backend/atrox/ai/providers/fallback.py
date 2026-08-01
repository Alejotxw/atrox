"""Proveedor compuesto con respaldo (fallback) entre motores LLM (HU-012).

Delega en el primer proveedor de la cadena que responda con éxito. Si un
proveedor lanza `LLMGenerationError` (red caída, HTTP error, formato
inválido) se registra el fallo y se prueba el siguiente. Si todos fallan,
se propaga el último error: la lógica de negocio siempre recibe el mismo
contrato `LLMProvider.generate`, sin saber qué motor respondió.
"""

import logging
from typing import Any, Sequence

from atrox.ai.providers.base import LLMGenerationError, LLMProvider, LLMResult

logger = logging.getLogger(__name__)


class FallbackLLMProvider:
    """Encadena proveedores LLM y usa el primero que responda (ADR-005)."""

    def __init__(self, providers: Sequence[LLMProvider]) -> None:
        if not providers:
            raise ValueError("FallbackLLMProvider requiere al menos un proveedor")
        self.providers = list(providers)

    @property
    def name(self) -> str:
        return "+".join(provider.name for provider in self.providers)

    @property
    def model(self) -> str:
        return self.providers[0].model

    async def generate(self, prompt: str, schema: dict[str, Any]) -> LLMResult:
        last_error: LLMGenerationError | None = None
        for provider in self.providers:
            try:
                result = await provider.generate(prompt, schema)
                logger.info(
                    "LLM respondió con proveedor %s (modelo %s)",
                    provider.name,
                    provider.model,
                )
                return result
            except LLMGenerationError as exc:
                last_error = exc
                logger.warning("Proveedor LLM %s falló: %s", provider.name, exc)

        if last_error is None:
            last_error = LLMGenerationError("Ningún proveedor LLM respondió")
        raise last_error
