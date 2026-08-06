"""Errores controlados de validación de respuestas IA (HU-017)."""

from __future__ import annotations

from typing import Any


class LLMResponseError(Exception):
    """Base para todos los errores de validación de respuestas IA.

    Nunca un crash: los componentes que consumen salidas del LLM
    (motor de escaneo, reportes) solo reciben datos ya validados.
    """


class InvalidJSONError(LLMResponseError):
    """La respuesta cruda del LLM no contiene JSON sintácticamente válido."""


class SchemaRejectionError(LLMResponseError):
    """El JSON es válido pero no cumple el esquema Pydantic esperado."""

    def __init__(self, message: str, *, errors: list[Any] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []


class UnknownOutputKindError(LLMResponseError, KeyError):
    """Se solicitó validar un tipo de salida IA no registrado en el esquema."""


class ValidationRetriesExhaustedError(LLMResponseError):
    """La respuesta IA fue rechazada en todos los intentos permitidos."""
