"""Router de validación estructurada de respuestas IA (HU-017)."""

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel, Field

from atrox.ai.schemas.errors import LLMResponseError, UnknownOutputKindError
from atrox.ai.schemas.rejections import RejectionLogger
from atrox.ai.schemas.registry import get_output_model
from atrox.ai.schemas.validator import validate_raw

router = APIRouter(prefix="/api/ai/validate", tags=["ai-validate"])


class ValidationRequest(BaseModel):
    """Respuesta cruda del LLM a validar contra el esquema de `kind`."""

    kind: str = Field(description="Tipo de salida IA: vectors | payloads | scores")
    raw: str = Field(description="Respuesta cruda del LLM (JSON, bloque markdown o prosa con JSON)")


class ValidationResponse(BaseModel):
    """Envoltorio de la validación: datos validados o rechazo controlado."""

    valid: bool
    kind: str
    data: dict | None = None
    error: str | None = None
    detail: str | None = None
    rejection_id: str | None = None


def _get_rejection_logger(request: Request) -> RejectionLogger:
    state = getattr(request.app.state, "llm_rejections", None)
    if state is not None:
        return state
    return RejectionLogger()


@router.post("", response_model=ValidationResponse)
async def validate_llm_response(
    body: ValidationRequest,
    request: Request,
    response: Response,
) -> ValidationResponse:
    """
    Valida una respuesta cruda del LLM contra el esquema Pydantic esperado
    (HU-017).

    Devuelve `200` con `valid: true` y el modelo validado si cumple el esquema;
    o `422` con `valid: false`, el error controlado y el id del rechazo
    logueado para depuración. Un `kind` no registrado también responde `422`
    sin registrar rechazo (no es una respuesta del LLM). Nunca se devuelven
    datos malformados.
    """
    logger = _get_rejection_logger(request)

    try:
        model = validate_raw(body.raw, get_output_model(body.kind))
    except UnknownOutputKindError as exc:
        response.status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
        return ValidationResponse(
            valid=False, kind=body.kind, error=type(exc).__name__, detail=str(exc)
        )
    except LLMResponseError as exc:
        record = await logger.record(
            kind=body.kind,
            error=type(exc).__name__,
            detail=str(exc),
            raw=body.raw,
            attempt=1,
        )
        response.status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
        return ValidationResponse(
            valid=False,
            kind=body.kind,
            error=type(exc).__name__,
            detail=str(exc),
            rejection_id=record.id,
        )

    return ValidationResponse(valid=True, kind=body.kind, data=model.model_dump(mode="json"))
