"""Chat real de IA sobre hallazgos de escaneo (Motor Ollama IA, HU-012/ADR-002).

A diferencia del análisis de vectores (`llm_analyzer.py`), no hay motor
heurístico de respaldo — una conversación abierta no tiene sustituto basado
en reglas. Si el LLM no está configurado o no responde, el llamador debe
devolver un error claro al usuario, nunca inventar una respuesta.
"""

import json

from atrox.ai.agents.chat.models import LLMChatPayload
from atrox.ai.providers.base import LLMProvider
from atrox.ai.schemas.rejections import RejectionLogger
from atrox.ai.schemas.validator import LLMResponseValidator

_SYSTEM_INSTRUCTIONS = """Eres el asistente de IA de Atrox, un framework de pentesting. Respondes preguntas de un analista de seguridad sobre los hallazgos de un escaneo real. Responde SIEMPRE en español, sin importar en qué idioma esté redactada esta instrucción. Sé claro, técnico y directo — no repitas la pregunta, no des advertencias legales genéricas (el usuario ya tiene autorización para el pentest).

Responde ÚNICAMENTE con un objeto JSON que cumpla exactamente este esquema, sin texto adicional ni bloques markdown:
{schema}"""


def build_prompt(message: str, context: str | None) -> str:
    schema = json.dumps(LLMChatPayload.model_json_schema(), ensure_ascii=False)
    instructions = _SYSTEM_INSTRUCTIONS.format(schema=schema)
    context_block = f"\n\nContexto del escaneo actual:\n{context}" if context else ""
    return f"{instructions}{context_block}\n\nPregunta del analista:\n{message}"


async def ask(
    message: str,
    context: str | None,
    provider: LLMProvider,
    *,
    rejection_logger: RejectionLogger | None = None,
    max_retries: int = 1,
) -> str:
    """Pide al LLM una respuesta a la pregunta del analista.

    Deja propagar `LLMGenerationError`/`LLMResponseError` — el llamador
    (router) debe traducirlos a un error HTTP claro, nunca inventar una
    respuesta cuando el LLM no está disponible.
    """
    prompt = build_prompt(message, context)
    schema = LLMChatPayload.model_json_schema()

    async def _invoke() -> str:
        result = await provider.generate(prompt, schema)
        return result.raw_text

    validator = LLMResponseValidator(rejection_logger=rejection_logger, max_retries=max_retries)
    payload = await validator.validate(_invoke, kind="chat", model_name=provider.model)
    return payload.response
