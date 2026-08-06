"""Validador estructurado de respuestas IA con Pydantic (HU-017 / ADR-002).

Flujo:
1. Extrae el JSON de la respuesta cruda (acepta bloques markdown ```json,
   JSON plano o prosa con JSON embebido).
2. Lo parsea; si es JSON inválido → `InvalidJSONError` (error controlado).
3. Lo valida contra el esquema Pydantic registrado para el tipo de salida
   (vectors / payloads / scores); si no lo cumple → `SchemaRejectionError`.
4. Cada rechazo se registra en el log de rechazos (HU-017) y, si quedan
   intentos, se re-consulta al LLM (`llm_invoke`); agotados, se lanza
   `ValidationRetriesExhaustedError`.

Ninguna respuesta malformada llega al motor de escaneo ni a los reportes.
"""

from __future__ import annotations

import json
import re
from typing import Awaitable, Callable, Generic, TypeVar

from pydantic import BaseModel, ValidationError

from atrox.ai.schemas.errors import (
    InvalidJSONError,
    LLMResponseError,
    SchemaRejectionError,
    ValidationRetriesExhaustedError,
)
from atrox.ai.schemas.rejections import RejectionLogger
from atrox.ai.schemas.registry import get_output_model

ModelT = TypeVar("ModelT", bound=BaseModel)

LLMInvoke = Callable[[], Awaitable[str]]

_MARKDOWN_FENCE_RE = re.compile(r"```(?:json|jsonl)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def extract_json_object(raw: str) -> str:
    """Extrae el primer objeto/arreglo JSON balanceado del texto crudo."""
    if not raw or not raw.strip():
        raise InvalidJSONError("La respuesta del LLM está vacía.")

    fenced = _MARKDOWN_FENCE_RE.search(raw)
    candidate = fenced.group(1) if fenced else raw

    start = -1
    open_ch = ""
    depth = 0
    in_string = False
    escape = False

    for idx, ch in enumerate(candidate):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            if depth == 0:
                start = idx
                open_ch = ch
            depth += 1
        elif ch in "}]":
            if depth > 0:
                depth -= 1
                if depth == 0:
                    return candidate[start : idx + 1]

    raise InvalidJSONError("No se encontró un JSON balanceado en la respuesta.")


def validate_raw(raw: str, model_cls: type[ModelT]) -> ModelT:
    """Valida la respuesta cruda del LLM contra un esquema Pydantic."""
    candidate = extract_json_object(raw)

    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise InvalidJSONError(
            f"JSON inválido: {exc.msg} (línea {exc.lineno}, columna {exc.colno})"
        ) from exc

    try:
        return model_cls.model_validate(payload)
    except ValidationError as exc:
        raise SchemaRejectionError(
            f"El JSON no cumple el esquema '{model_cls.__name__}': "
            f"{len(exc.errors())} error(es)",
            errors=exc.errors(),
        ) from exc


class LLMResponseValidator(Generic[ModelT]):
    """Valida respuestas del LLM contra el esquema registrado, con reintento.

    - Cada respuesta rechazada se registra en el log de rechazos (HU-017).
    - Ante JSON inválido o esquema no cumplido se reintenta hasta `max_retries`
      veces (`ATROX_LLM_VALIDATION_MAX_RETRIES` por defecto, sobre-escribible
      por llamada); agotados los intentos se lanza un error controlado
      (`ValidationRetriesExhaustedError`), nunca un crash.
    """

    def __init__(
        self,
        *,
        rejection_logger: RejectionLogger | None = None,
        max_retries: int | None = None,
    ) -> None:
        self._rejections = rejection_logger or RejectionLogger()
        self._max_retries = max_retries

    @property
    def rejection_logger(self) -> RejectionLogger:
        return self._rejections

    async def validate(
        self,
        llm_invoke: LLMInvoke,
        *,
        kind: str,
        max_retries: int | None = None,
        model_name: str = "llm",
    ) -> ModelT:
        model_cls = get_output_model(kind)
        retries = self._max_retries if max_retries is None else max_retries
        retries = max(0, retries or 0)

        last_error: LLMResponseError | None = None
        for attempt in range(1, retries + 2):
            raw = await llm_invoke()
            try:
                return validate_raw(raw, model_cls)
            except LLMResponseError as exc:
                last_error = exc
                await self._rejections.record(
                    kind=kind,
                    model_name=model_name,
                    error=type(exc).__name__,
                    detail=str(exc),
                    raw=raw,
                    attempt=attempt,
                )
                if attempt <= retries:
                    continue
                break

        raise ValidationRetriesExhaustedError(
            f"Respuesta IA rechazada tras {retries + 1} intento(s) "
            f"({type(last_error).__name__}): {last_error}"
        ) from last_error
