"""Router del chat de IA sobre hallazgos de escaneo (Motor Ollama IA)."""

from fastapi import APIRouter, HTTPException, Request

from atrox.ai.agents.chat.chat_agent import ask
from atrox.ai.agents.chat.models import ChatRequest, ChatResponse
from atrox.ai.providers.base import LLMGenerationError
from atrox.ai.providers.factory import build_llm_provider
from atrox.ai.schemas.errors import LLMResponseError
from atrox.config import get_settings

router = APIRouter(prefix="/api/ai/chat", tags=["ai-chat"])


@router.post("", response_model=ChatResponse)
async def chat(body: ChatRequest, request: Request) -> ChatResponse:
    """Responde una pregunta del analista sobre los hallazgos actuales.

    A diferencia de `/api/ai/vectors/analyze`, no hay motor heurístico de
    respaldo: si no hay un proveedor LLM real configurado, o si no responde,
    se retorna un error claro en vez de una respuesta inventada.
    """
    settings = get_settings()
    if settings.llm_provider == "mock":
        raise HTTPException(
            status_code=503,
            detail=(
                "El Motor de IA no está configurado. Defina ATROX_LLM_PROVIDER=ollama "
                "(y opcionalmente ATROX_LLM_OLLAMA_MODEL) en el backend."
            ),
        )

    provider = build_llm_provider(settings)
    rejection_logger = getattr(request.app.state, "llm_rejections", None)

    try:
        response_text = await ask(
            body.message,
            body.context,
            provider,
            rejection_logger=rejection_logger,
        )
    except (LLMGenerationError, LLMResponseError) as exc:
        raise HTTPException(
            status_code=502,
            detail=f"El modelo de IA no respondió correctamente: {exc}",
        ) from exc

    return ChatResponse(response=response_text, model_used=provider.model)
