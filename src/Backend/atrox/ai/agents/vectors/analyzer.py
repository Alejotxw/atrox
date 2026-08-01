"""Agente de análisis de vectores de ataque (HU-014 / RF-003)."""

import time

from atrox.ai.agents.vectors.correlator import correlate_findings
from atrox.ai.agents.vectors.models import VectorAnalysisResult
from atrox.scanner.models import VulnFinding

SLA_MS = 5000
MAX_BATCH_SIZE = 10


class VectorAnalysisAgent:
    """Correlaciona hallazgos de escaneo y propone cadenas de ataque priorizadas."""

    def analyze(self, findings: list[VulnFinding]) -> VectorAnalysisResult:
        if len(findings) > MAX_BATCH_SIZE:
            findings = findings[:MAX_BATCH_SIZE]

        start = time.perf_counter()
        vectors = correlate_findings(findings)
        elapsed_ms = (time.perf_counter() - start) * 1000

        return VectorAnalysisResult(
            vectors=vectors,
            total_findings=len(findings),
            analysis_time_ms=round(elapsed_ms, 2),
            within_sla=elapsed_ms < SLA_MS,
        )

    async def analyze_async(self, findings: list[VulnFinding]) -> VectorAnalysisResult:
        """Wrapper async — correlación CPU-bound rápida, sin bloqueo significativo."""
        return self.analyze(findings)
