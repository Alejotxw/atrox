from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from atrox.persistence.deps import get_persistence
from atrox.persistence.models import ReportCreate, ReportRecord
from atrox.persistence.service import EncryptedPersistenceService

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("", status_code=201, response_model=ReportRecord)
async def create_report(
    body: ReportCreate,
    store: EncryptedPersistenceService = Depends(get_persistence),
) -> ReportRecord:
    """Persiste un reporte cifrando contenido sensible en reposo."""
    return await store.save_report(body)


@router.get("", response_model=list[ReportRecord])
async def list_reports(
    store: EncryptedPersistenceService = Depends(get_persistence),
) -> list[ReportRecord]:
    return await store.list_reports(decrypt=True)


@router.get("/{report_id}", response_model=ReportRecord)
async def get_report(
    report_id: UUID,
    store: EncryptedPersistenceService = Depends(get_persistence),
) -> ReportRecord:
    record = await store.get_report(report_id, decrypt=True)
    if record is None:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    return record
