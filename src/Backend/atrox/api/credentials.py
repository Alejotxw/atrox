from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from atrox.persistence.deps import get_persistence
from atrox.persistence.models import CredentialCreate, CredentialRecord
from atrox.persistence.service import EncryptedPersistenceService

router = APIRouter(prefix="/api/credentials", tags=["credentials"])


@router.post("", status_code=201, response_model=CredentialRecord)
async def create_credential(
    body: CredentialCreate,
    store: EncryptedPersistenceService = Depends(get_persistence),
) -> CredentialRecord:
    """Persiste una credencial con password/secret/token cifrados en reposo."""
    return await store.save_credential(body)


@router.get("", response_model=list[CredentialRecord])
async def list_credentials(
    store: EncryptedPersistenceService = Depends(get_persistence),
) -> list[CredentialRecord]:
    return await store.list_credentials(decrypt=True)


@router.get("/{credential_id}", response_model=CredentialRecord)
async def get_credential(
    credential_id: UUID,
    store: EncryptedPersistenceService = Depends(get_persistence),
) -> CredentialRecord:
    record = await store.get_credential(credential_id, decrypt=True)
    if record is None:
        raise HTTPException(status_code=404, detail="Credencial no encontrada")
    return record
