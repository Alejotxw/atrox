from fastapi import APIRouter, Depends, Request

from atrox.ai.agents.vectors.analyzer import VectorAnalysisAgent
from atrox.ai.agents.vectors.models import VectorAnalysisRequest, VectorAnalysisResult
from atrox.ai.providers.factory import build_llm_provider
from atrox.config import get_settings

router = APIRouter(prefix="/api/ai/vectors", tags=["ai-vectors"])


def get_vector_agent(request: Request) -> VectorAnalysisAgent:
    settings = get_settings()
    provider = build_llm_provider(settings) if settings.llm_provider != "mock" else None
    rejection_logger = getattr(request.app.state, "llm_rejections", None)
    return VectorAnalysisAgent(llm_provider=provider, rejection_logger=rejection_logger)


@router.post("/analyze", response_model=VectorAnalysisResult)
async def analyze_attack_vectors(
    body: VectorAnalysisRequest,
    agent: VectorAnalysisAgent = Depends(get_vector_agent),
) -> VectorAnalysisResult:
    """
    Correlaciona hallazgos de escaneo (HU-003/HU-006) y retorna
    vectores de ataque ordenados por impacto con justificación.
    """
    return await agent.analyze_async(body.findings)
