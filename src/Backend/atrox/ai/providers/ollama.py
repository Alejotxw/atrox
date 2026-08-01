"""Proveedor local Ollama (HU-012 / ADR-002).

Ejecuta modelos locales (ej. llama3) vía la API HTTP de Ollama (`/api/chat`).
No envía datos a la nube — apto para auditorías air-gapped. Usa `httpx`
async con cliente inyectable (mismo patrón que `NvdClient.http_client`).
"""

import logging
from typing import Any

import httpx

from atrox.ai.providers.base import LLMGenerationError, LLMResult, parse_json_text

logger = logging.getLogger(__name__)

OLLAMA_DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaProvider:
    """Proveedor local para modelos servidos por Ollama."""

    name = "ollama"

    def __init__(
        self,
        *,
        model: str = "llama3",
        base_url: str = OLLAMA_DEFAULT_BASE_URL,
        timeout_seconds: int = 30,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self._http_client = http_client

    async def generate(self, prompt: str, schema: dict[str, Any]) -> LLMResult:
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "format": schema or "json",
            "options": {"temperature": 0},
        }

        client = self._http_client
        if client is None:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as owned:
                return await self._request(owned, url, payload)
        return await self._request(client, url, payload)

    async def _request(
        self,
        client: httpx.AsyncClient,
        url: str,
        payload: dict,
    ) -> LLMResult:
        try:
            response = await client.post(url, json=payload)
        except (httpx.HTTPError, OSError) as exc:
            raise LLMGenerationError(f"Error de red al llamar a Ollama: {exc}") from exc

        if response.status_code != 200:
            raise LLMGenerationError(
                f"Ollama respondió HTTP {response.status_code}: {response.text[:300]}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise LLMGenerationError("Ollama devolvió una respuesta no-JSON") from exc

        message = data.get("message") or {}
        text = message.get("content")
        if not text:
            raise LLMGenerationError("Ollama devolvió una respuesta sin contenido")

        content = parse_json_text(text)
        return LLMResult(provider=self.name, model=self.model, content=content, raw_text=text)
