"""Router del agente de scoring de confianza (HU-016)."""

from fastapi import APIRouter, Depends

from atrox.ai.agents.scoring.models import ConfidenceScoreResult, ScoringRequest
from atrox.ai.agents.scoring.scorer import ConfidenceScoringAgent

router = APIRouter(prefix="/api/ai/scoring", tags=["ai-scoring"])


def get_scoring_agent() -> ConfidenceScoringAgent:
    return ConfidenceScoringAgent()


@router.post("/score", response_model=ConfidenceScoreResult)
async def score_finding_confidence(
    body: ScoringRequest,
    agent: ConfidenceScoringAgent = Depends(get_scoring_agent),
) -> ConfidenceScoreResult:
    """
    Asigna un score de confianza 0-100 a un hallazgo (HU-003/HU-006),
    marcándolo como `probable_fp` si cae bajo el umbral configurado
    (`ATROX_FP_SCORE_THRESHOLD`, sobre-escribible por request vía
    `threshold`), con una explicación breve de las señales heurísticas
    usadas (RF-005).
    """
    return await agent.score_async(body)
