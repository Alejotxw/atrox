"""Proveedor Cloud Gemini (HU-012 / ADR-002).

Usa la REST API `generateContent` de Gemini vía `httpx` async con cliente
inyectable (mismo patrón que `NvdClient.http_client`). La salida estructurada
se solicita con `responseMimeType=application/json` + `responseSchema`.

Si `api_key` no está configurada, `generate` lanza `LLMGenerationError` en
runtime — así un Gemini configurado solo como respaldo no rompe el arranque
y la ausencia de clave se comporta como un fallo de proveedor que el
`FallbackLLMProvider` puede cubrir.
"""

import logging
from typing import Any

import httpx

from atrox.ai.providers.base import LLMGenerationError, LLMResult, parse_json_text

logger = logging.getLogger(__name__)

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"


class GeminiProvider:
    """Proveedor Cloud para modelos Gemini (ej. gemini-2.0-flash)."""

    name = "gemini"

    def __init__(
        self,
        *,
        api_key: str,
        model: str = "gemini-2.0-flash",
        base_url: str = GEMINI_BASE_URL,
        timeout_seconds: int = 180,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self._http_client = http_client

    async def generate(self, prompt: str, schema: dict[str, Any]) -> LLMResult:
        if not self.api_key:
            raise LLMGenerationError(
                "GeminiProvider requiere ATROX_LLM_API_KEY (configuración del proveedor)"
            )

        url = f"{self.base_url}/models/{self.model}:generateContent"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": schema,
                "temperature": 0,
            },
        }
        headers = {"x-goog-api-key": self.api_key}

        text = await self._post_and_read_text(url, headers, payload)
        content = parse_json_text(text)
        return LLMResult(provider=self.name, model=self.model, content=content, raw_text=text)

    async def _post_and_read_text(self, url: str, headers: dict[str, str], payload: dict) -> str:
        client = self._http_client
        if client is None:
            timeout = httpx.Timeout(
                connect=10.0,
                read=float(self.timeout_seconds),
                write=30.0,
                pool=10.0,
            )
            async with httpx.AsyncClient(timeout=timeout) as owned:
                return await self._request(owned, url, headers, payload)
        return await self._request(client, url, headers, payload)

    async def _request(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        payload: dict,
    ) -> str:
        try:
            response = await client.post(url, headers=headers, json=payload)
        except (httpx.HTTPError, OSError) as exc:
            raise LLMGenerationError(f"Error de red al llamar a Gemini: {exc}") from exc

        if response.status_code != 200:
            raise LLMGenerationError(
                f"Gemini respondió HTTP {response.status_code}: {response.text[:300]}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise LLMGenerationError("Gemini devolvió una respuesta no-JSON") from exc

        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMGenerationError(
                "Gemini devolvió una respuesta sin candidatos/texto utilizable"
            ) from exc
        return text
