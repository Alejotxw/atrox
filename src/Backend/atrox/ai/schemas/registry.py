"""Registro central de esquemas Pydantic para salidas del LLM (HU-017).

Cada tipo de salida que el LLM puede producir (vectores, payloads, scores)
mapea a un modelo Pydantic que ya vive en el agente correspondiente
(HU-014/HU-015/HU-016). El validador rechaza cualquier respuesta que no
cumpla exactamente ese esquema antes de que llegue al motor de escaneo
o a los reportes (RF-003/RF-004/RF-005 · ADR-002).
"""

from __future__ import annotations

from pydantic import BaseModel

from atrox.ai.agents.payloads.models import PayloadGenerationResult
from atrox.ai.agents.scoring.models import ConfidenceScoreResult
from atrox.ai.agents.vectors.models import VectorAnalysisResult
from atrox.ai.schemas.errors import UnknownOutputKindError

LLM_OUTPUT_MODELS: dict[str, type[BaseModel]] = {
    "vectors": VectorAnalysisResult,
    "payloads": PayloadGenerationResult,
    "scores": ConfidenceScoreResult,
}

SUPPORTED_KINDS: frozenset[str] = frozenset(LLM_OUTPUT_MODELS)


def get_output_model(kind: str) -> type[BaseModel]:
    """Retorna el esquema Pydantic para un tipo de salida IA registrado."""
    try:
        return LLM_OUTPUT_MODELS[kind]
    except KeyError:
        raise UnknownOutputKindError(
            f"Tipo de salida desconocido '{kind}'. "
            f"Soportados: {sorted(SUPPORTED_KINDS)}"
        ) from None
