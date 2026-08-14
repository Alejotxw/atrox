"""Análisis real de vectores de ataque vía LLM (HU-014 + HU-012/ADR-002).

Complementa al motor heurístico (`correlator.py`), que sigue siendo el
respaldo: si no hay proveedor LLM real configurado (`ATROX_LLM_PROVIDER`),
si el LLM no responde, o si su salida no valida contra el esquema esperado,
el llamador debe usar `correlate_findings()` — nunca se bloquea la auditoría
por un LLM caído o mal configurado.
"""

import json

from atrox.ai.agents.vectors.models import AttackVector, AttackVectorLLMPayload
from atrox.ai.providers.base import LLMProvider
from atrox.ai.schemas.rejections import RejectionLogger
from atrox.ai.schemas.validator import LLMResponseValidator
from atrox.scanner.models import VulnFinding

# Prompt corto a propósito: menos tokens de entrada = menos latencia en Ollama.
_SYSTEM_INSTRUCTIONS = """Analista de pentesting. Con estos hallazgos, propone vectores de ataque encadenados.
Responde SOLO JSON con este esquema (sin markdown):
{schema}

Reglas breves:
- chain: pasos accionables en español.
- justification: 1-2 frases de impacto real.
- estimated_impact: consecuencia de negocio concreta.
- severity_score: 0-10; rank: 1 = mayor prioridad.
- vector_id: id corto; finding_ids: solo template_id.
- Encadena hallazgos relacionados en un solo vector. No inventes hallazgos."""

_DESC_MAX = 160


def _truncate(text: str, limit: int = _DESC_MAX) -> str:
    cleaned = " ".join((text or "").split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1] + "…"


def _describe_finding(finding: VulnFinding) -> str:
    return (
        f'- "{finding.template_id}" | {finding.severity.value} | '
        f"{_truncate(finding.name, 80)} | "
        f"{_truncate(finding.matched_at or finding.host, 100)} | "
        f"ip {finding.ip or '?'} | "
        f"{_truncate(finding.description or '-', _DESC_MAX)}"
    )


def build_prompt(findings: list[VulnFinding]) -> str:
    """Arma un prompt compacto con los hallazgos priorizados del escaneo."""
    schema = json.dumps(AttackVectorLLMPayload.model_json_schema(), ensure_ascii=False)
    findings_block = "\n".join(_describe_finding(f) for f in findings)
    instructions = _SYSTEM_INSTRUCTIONS.format(schema=schema)
    return f"{instructions}\n\nHallazgos:\n{findings_block}"


async def analyze_with_llm(
    findings: list[VulnFinding],
    provider: LLMProvider,
    *,
    rejection_logger: RejectionLogger | None = None,
    max_retries: int = 0,
) -> list[AttackVector]:
    """Pide al LLM un análisis real de qué puede lograr un atacante con los hallazgos.

    `max_retries=0` por defecto: un solo intento. Un reintento duplica la espera
    en modelos locales lentos y suele cortar la auditoría por timeout.

    Deja propagar `LLMGenerationError` / errores de validación — el llamador
    (`VectorAnalysisAgent`) debe capturarlos y usar el motor heurístico.
    """
    prompt = build_prompt(findings)
    schema = AttackVectorLLMPayload.model_json_schema()

    async def _invoke() -> str:
        result = await provider.generate(prompt, schema)
        return result.raw_text

    validator = LLMResponseValidator(rejection_logger=rejection_logger, max_retries=max_retries)
    payload = await validator.validate(
        _invoke,
        kind="vector_narrative",
        model_name=provider.model,
    )
    return payload.vectors
