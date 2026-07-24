from fastapi import APIRouter, Depends

from atrox.ai.agents.vectors.analyzer import VectorAnalysisAgent
from atrox.ai.agents.vectors.models import VectorAnalysisRequest, VectorAnalysisResult

router = APIRouter(prefix="/api/ai/vectors", tags=["ai-vectors"])


def get_vector_agent() -> VectorAnalysisAgent:
    return VectorAnalysisAgent()


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
