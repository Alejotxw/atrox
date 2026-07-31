"""Agente de generación de payloads contextualizados (HU-015 / RF-004)."""

import time

from atrox.ai.agents.payloads.library import build_suggestions, infer_category, infer_service
from atrox.ai.agents.payloads.models import PayloadGenerationRequest, PayloadGenerationResult

SLA_MS = 5000


class PayloadGeneratorAgent:
    """Sugiere payloads adaptados a la vulnerabilidad y servicio de un hallazgo.

    No ejecuta ningún payload ni realiza llamadas de red o subprocesos: es
    un catálogo heurístico consultado en memoria, seguro de invocar en
    cualquier entorno (revisión de seguridad en ADR-004).
    """

    def generate(self, request: PayloadGenerationRequest) -> PayloadGenerationResult:
        finding = request.finding
        finding_id = request.finding_id or finding.template_id

        start = time.perf_counter()
        category = infer_category(finding)
        service = infer_service(finding)
        suggestions = build_suggestions(category)
        elapsed_ms = (time.perf_counter() - start) * 1000

        return PayloadGenerationResult(
            finding_id=finding_id,
            service=service,
            category=category,
            suggestions=suggestions,
            generation_time_ms=round(elapsed_ms, 2),
            within_sla=elapsed_ms < SLA_MS,
        )

    async def generate_async(self, request: PayloadGenerationRequest) -> PayloadGenerationResult:
        """Wrapper async — generación heurística en memoria, sin bloqueo significativo."""
        return self.generate(request)
