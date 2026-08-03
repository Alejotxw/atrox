from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from atrox.persistence.deps import get_persistence
from atrox.persistence.models import FindingCreate, FindingRecord
from atrox.persistence.service import EncryptedPersistenceService

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.post("", status_code=201, response_model=FindingRecord)
async def create_finding(
    body: FindingCreate,
    store: EncryptedPersistenceService = Depends(get_persistence),
) -> FindingRecord:
    """Persiste un hallazgo cifrando campos sensibles en reposo."""
    return await store.save_finding(body)


@router.get("", response_model=list[FindingRecord])
async def list_findings(
    store: EncryptedPersistenceService = Depends(get_persistence),
) -> list[FindingRecord]:
    """Lista hallazgos descifrados (uso autorizado vía API)."""
    return await store.list_findings(decrypt=True)


@router.get("/{finding_id}", response_model=FindingRecord)
async def get_finding(
    finding_id: UUID,
    store: EncryptedPersistenceService = Depends(get_persistence),
) -> FindingRecord:
    record = await store.get_finding(finding_id, decrypt=True)
    if record is None:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")
    return record
