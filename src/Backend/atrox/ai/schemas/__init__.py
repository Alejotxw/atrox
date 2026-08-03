"""Validación estructurada de respuestas IA con Pydantic (HU-017)."""

from atrox.ai.schemas.errors import (
    InvalidJSONError,
    LLMResponseError,
    SchemaRejectionError,
    UnknownOutputKindError,
    ValidationRetriesExhaustedError,
)
from atrox.ai.schemas.rejections import (
    RAW_MAX_LEN,
    RejectionLogger,
    RejectionLogStore,
    RejectionRecord,
    build_rejection_logger,
)
from atrox.ai.schemas.registry import LLM_OUTPUT_MODELS, SUPPORTED_KINDS, get_output_model
from atrox.ai.schemas.validator import (
    LLMInvoke,
    LLMResponseValidator,
    extract_json_object,
    validate_raw,
)

__all__ = [
    "InvalidJSONError",
    "LLMResponseError",
    "SchemaRejectionError",
    "UnknownOutputKindError",
    "ValidationRetriesExhaustedError",
    "RAW_MAX_LEN",
    "RejectionLogger",
    "RejectionLogStore",
    "RejectionRecord",
    "build_rejection_logger",
    "LLM_OUTPUT_MODELS",
    "SUPPORTED_KINDS",
    "get_output_model",
    "LLMInvoke",
    "LLMResponseValidator",
    "extract_json_object",
    "validate_raw",
]
