"""Modelos del chat de IA sobre hallazgos de escaneo (Motor Ollama IA)."""

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    context: str | None = Field(
        default=None,
        max_length=4000,
        description="Resumen en texto plano de los hallazgos actuales, generado por el frontend",
    )


class ChatResponse(BaseModel):
    response: str
    model_used: str


class LLMChatPayload(BaseModel):
    """Esquema exacto que debe cumplir la respuesta cruda del LLM."""

    response: str
