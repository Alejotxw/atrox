"""Router del agente de generación de payloads (HU-015)."""

from fastapi import APIRouter, Depends, Header, Request

from atrox.ai.agents.payloads.generator import PayloadGeneratorAgent
from atrox.ai.agents.payloads.models import PayloadGenerationRequest, PayloadGenerationResult

router = APIRouter(prefix="/api/ai/payloads", tags=["ai-payloads"])


def get_payload_agent() -> PayloadGeneratorAgent:
    return PayloadGeneratorAgent()


@router.post("/generate", response_model=PayloadGenerationResult)
async def generate_payloads(
    body: PayloadGenerationRequest,
    request: Request,
    agent: PayloadGeneratorAgent = Depends(get_payload_agent),
    x_atrox_user: str | None = Header(default=None, alias="X-Atrox-User"),
) -> PayloadGenerationResult:
    """
    Sugiere payloads adaptados a la vulnerabilidad y servicio detectado en un
    hallazgo (HU-003/HU-006), asociados a un `finding_id`, para acelerar la
    validación controlada en laboratorio (RF-004). Uso exclusivo en entornos
    autorizados — ver `disclaimer` en la respuesta.
    """
    result = await agent.generate_async(body)

    audit_log = getattr(request.app.state, "audit_log", None)
    if audit_log is not None:
        await audit_log.record(
            user=x_atrox_user or "system",
            action="payload.generated",
            resource=f"finding:{result.finding_id}",
            metadata={"category": result.category, "service": result.service},
        )

    return result
