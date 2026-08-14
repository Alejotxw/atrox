"""Agente de análisis de vectores de ataque (HU-014 / RF-003)."""

import logging
import time

from atrox.ai.agents.vectors.correlator import correlate_findings
from atrox.ai.agents.vectors.llm_analyzer import analyze_with_llm
from atrox.ai.agents.vectors.models import VectorAnalysisResult
from atrox.ai.providers.base import LLMGenerationError, LLMProvider
from atrox.ai.schemas.errors import LLMResponseError
from atrox.ai.schemas.rejections import RejectionLogger
from atrox.scanner.models import VulnFinding, VulnSeverity

logger = logging.getLogger(__name__)

SLA_MS = 5000
MAX_BATCH_SIZE = 10

_SEVERITY_RANK = {
    VulnSeverity.CRITICAL: 0,
    VulnSeverity.HIGH: 1,
    VulnSeverity.MEDIUM: 2,
    VulnSeverity.LOW: 3,
    VulnSeverity.INFO: 4,
    VulnSeverity.UNKNOWN: 5,
}


def prioritize_findings(findings: list[VulnFinding], limit: int = MAX_BATCH_SIZE) -> list[VulnFinding]:
    """Ordena por severidad (crítica primero) y recorta el lote para el LLM."""
    ordered = sorted(
        findings,
        key=lambda f: (_SEVERITY_RANK.get(f.severity, 99), f.template_id),
    )
    return ordered[:limit]


class VectorAnalysisAgent:
    """Correlaciona hallazgos de escaneo y propone cadenas de ataque priorizadas.

    Intenta análisis real vía LLM (`llm_provider`, ver ADR-005) primero; si no
    está configurado, no responde, o su salida no valida, cae al motor
    heurístico (`correlator.py`) — la auditoría nunca falla por esto.
    """

    def __init__(
        self,
        llm_provider: LLMProvider | None = None,
        rejection_logger: RejectionLogger | None = None,
    ) -> None:
        self._llm_provider = llm_provider
        self._rejection_logger = rejection_logger

    def analyze(self, findings: list[VulnFinding]) -> VectorAnalysisResult:
        findings = prioritize_findings(findings)

        start = time.perf_counter()
        vectors = correlate_findings(findings)
        elapsed_ms = (time.perf_counter() - start) * 1000

        return VectorAnalysisResult(
            vectors=vectors,
            total_findings=len(findings),
            analysis_time_ms=round(elapsed_ms, 2),
            within_sla=elapsed_ms < SLA_MS,
            source="heuristic",
        )

    async def analyze_async(self, findings: list[VulnFinding]) -> VectorAnalysisResult:
        """Intenta el LLM real primero; cae al motor heurístico si falla o tarda de más."""
        findings = prioritize_findings(findings)

        if self._llm_provider is not None and findings:
            start = time.perf_counter()
            try:
                vectors = await analyze_with_llm(
                    findings,
                    self._llm_provider,
                    rejection_logger=self._rejection_logger,
                    max_retries=0,
                )
                elapsed_ms = (time.perf_counter() - start) * 1000
                return VectorAnalysisResult(
                    vectors=vectors,
                    total_findings=len(findings),
                    analysis_time_ms=round(elapsed_ms, 2),
                    within_sla=elapsed_ms < SLA_MS,
                    source="llm",
                    model_used=self._llm_provider.model,
                )
            except (LLMGenerationError, LLMResponseError) as exc:
                logger.warning(
                    "Análisis de vectores vía LLM falló, usando motor heurístico: %s", exc
                )

        return self.analyze(findings)
