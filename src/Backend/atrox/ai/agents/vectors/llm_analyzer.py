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

_SYSTEM_INSTRUCTIONS = """Eres un analista senior de pentesting. Analiza estos hallazgos reales de un escaneo de vulnerabilidades como lo haría un atacante: identifica qué combinaciones son explotables en conjunto (cadenas de ataque), qué podría lograr un atacante concretamente con cada uno, y prioriza por impacto real de negocio — no repitas la descripción técnica de la vulnerabilidad, explica sus consecuencias prácticas.

Responde ÚNICAMENTE con un objeto JSON que cumpla exactamente este esquema, sin texto adicional ni bloques markdown:
{schema}

Reglas:
- "chain": pasos concretos y accionables que seguiría un atacante, en español, en orden.
- "justification": 2-3 frases explicando QUÉ puede lograr un atacante con este hallazgo específico (no una definición genérica de la vulnerabilidad).
- "estimated_impact": consecuencia de negocio concreta (ej. "acceso a base de datos de clientes", "control total del servidor web"), no solo la palabra "alto" o "crítico".
- "severity_score": número de 0 a 10, considerando severidad técnica Y explotabilidad real.
- "rank": 1 = mayor prioridad para un atacante real.
- "vector_id": identificador corto único (ej. "sqli-login-to-db").
- "finding_ids": SOLO el valor del template_id (ej. "sqli-login-blind"), NUNCA el prefijo "template_id=".
- Si dos o más hallazgos se pueden encadenar entre sí, represéntalos como UN solo vector con todos sus finding_ids.
- No inventes hallazgos que no estén en la lista."""


def _describe_finding(finding: VulnFinding) -> str:
    return (
        f'- ID "{finding.template_id}" · severidad {finding.severity.value} · '
        f"nombre {finding.name} · ubicación {finding.matched_at or finding.host} · "
        f"ip {finding.ip or 'desconocida'} · tags {', '.join(finding.tags) or 'ninguno'} · "
        f"descripción {finding.description or 'sin descripción'}"
    )


def build_prompt(findings: list[VulnFinding]) -> str:
    """Arma el prompt de análisis con los hallazgos reales del escaneo."""
    schema = json.dumps(AttackVectorLLMPayload.model_json_schema(), ensure_ascii=False)
    findings_block = "\n".join(_describe_finding(f) for f in findings)
    instructions = _SYSTEM_INSTRUCTIONS.format(schema=schema)
    return f"{instructions}\n\nHallazgos del escaneo:\n{findings_block}"


async def analyze_with_llm(
    findings: list[VulnFinding],
    provider: LLMProvider,
    *,
    rejection_logger: RejectionLogger | None = None,
    max_retries: int = 1,
) -> list[AttackVector]:
    """Pide al LLM un análisis real de qué puede lograr un atacante con los hallazgos.

    Deja propagar `LLMGenerationError` (LLM caído/no configurado) y
    `LLMResponseError`/`ValidationRetriesExhaustedError` (respuesta inválida
    tras reintentos) — el llamador (`VectorAnalysisAgent`) debe capturarlos y
    usar el motor heurístico como respaldo.
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
