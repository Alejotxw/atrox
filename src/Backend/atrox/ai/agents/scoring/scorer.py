"""Agente de scoring de confianza para filtrar falsos positivos (HU-016 / RF-005)."""

import time

from atrox.ai.agents.scoring.models import ConfidenceScoreResult, ScoringRequest
from atrox.ai.agents.scoring.rules import score_finding
from atrox.config import get_settings

SLA_MS = 5000


class ConfidenceScoringAgent:
    """Asigna un score de confianza 0-100 a un hallazgo para descartar ruido."""

    def score(self, request: ScoringRequest) -> ConfidenceScoreResult:
        finding = request.finding
        finding_id = request.finding_id or finding.template_id
        threshold = (
            request.threshold
            if request.threshold is not None
            else get_settings().fp_score_threshold
        )

        start = time.perf_counter()
        raw_score, reasons = score_finding(finding)
        elapsed_ms = (time.perf_counter() - start) * 1000

        explanation = "; ".join(reasons) + f" -> score {raw_score}/100 (umbral {threshold})"

        return ConfidenceScoreResult(
            finding_id=finding_id,
            score=raw_score,
            threshold=threshold,
            probable_fp=raw_score < threshold,
            explanation=explanation,
            generation_time_ms=round(elapsed_ms, 2),
            within_sla=elapsed_ms < SLA_MS,
        )

    async def score_async(self, request: ScoringRequest) -> ConfidenceScoreResult:
        """Wrapper async — heurística en memoria, sin bloqueo significativo."""
        return self.score(request)
