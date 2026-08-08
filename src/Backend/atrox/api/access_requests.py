import asyncio
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status

from atrox.access_requests.models import (
    AccessRequest,
    AccessRequestCreate,
    AccessRequestListResult,
    AccessRequestStatus,
    RejectAccessRequestRequest,
)
from atrox.access_requests.store import AccessRequestNotFoundError, AccessRequestStore
from atrox.accounts.models import ApproveAccessRequestResponse
from atrox.accounts.store import AccountStore
from atrox.api.accounts import account_to_public, get_account_store
from atrox.config import get_settings
from atrox.security.auth_deps import require_super_admin
from atrox.security.password_hasher import generate_temporary_password, hash_password

router = APIRouter(prefix="/api/access-requests", tags=["access-requests"])


def get_access_request_store(request: Request) -> AccessRequestStore:
    """Obtiene el AccessRequestStore desde el estado de la aplicación.

    Instancia por defecto si el lifespan no lo configuró (mismo patrón que
    `get_mfa_service`/`get_account_store`) — evita AttributeError en tests
    que no ejecutan el lifespan ni sobreescriben esta dependencia.
    """
    store = getattr(request.app.state, "access_request_store", None)
    if store is None:
        settings = get_settings()
        store = AccessRequestStore(store_path=Path(settings.access_request_store_path))
        request.app.state.access_request_store = store
    return store


@router.post("", status_code=201, response_model=AccessRequest)
async def submit_access_request(
    body: AccessRequestCreate,
    store: AccessRequestStore = Depends(get_access_request_store),
) -> AccessRequest:
    """Registra una solicitud de acceso enviada desde la página pública previa al login."""
    return await store.create(body)


@router.get(
    "",
    response_model=AccessRequestListResult,
    dependencies=[Depends(require_super_admin)],
)
async def list_access_requests(
    store: AccessRequestStore = Depends(get_access_request_store),
) -> AccessRequestListResult:
    """Lista las solicitudes de acceso pendientes de revisión (solo administrador)."""
    requests = await store.list_all()
    return AccessRequestListResult(total=len(requests), requests=requests)


def _require_pending(access_request: AccessRequest) -> None:
    if access_request.status != AccessRequestStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"La solicitud ya fue revisada (estado actual: {access_request.status.value})",
        )


@router.post(
    "/{request_id}/approve",
    response_model=ApproveAccessRequestResponse,
    dependencies=[Depends(require_super_admin)],
)
async def approve_access_request(
    request_id: UUID,
    request_store: AccessRequestStore = Depends(get_access_request_store),
    account_store: AccountStore = Depends(get_account_store),
) -> ApproveAccessRequestResponse:
    """Aprueba la solicitud: crea la cuenta y devuelve la contraseña temporal (solo se muestra una vez;
    no hay envío de correo automático — el administrador la comunica manualmente)."""
    access_request = await request_store.get(request_id)
    if access_request is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Solicitud de acceso no encontrada")
    _require_pending(access_request)

    temporary_password = generate_temporary_password()
    # scrypt es CPU-bound (ADR-001: no bloquear el loop async) — se offloadea a un hilo.
    password_hash = await asyncio.to_thread(hash_password, temporary_password)
    account = await account_store.create_from_request(access_request, password_hash=password_hash)
    try:
        await request_store.mark_approved(request_id, account_id=account.id)
    except AccessRequestNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return ApproveAccessRequestResponse(account=account_to_public(account), temporary_password=temporary_password)


@router.post(
    "/{request_id}/reject",
    response_model=AccessRequest,
    dependencies=[Depends(require_super_admin)],
)
async def reject_access_request(
    request_id: UUID,
    body: RejectAccessRequestRequest | None = None,
    request_store: AccessRequestStore = Depends(get_access_request_store),
) -> AccessRequest:
    """Rechaza la solicitud con un motivo opcional."""
    access_request = await request_store.get(request_id)
    if access_request is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Solicitud de acceso no encontrada")
    _require_pending(access_request)

    reason = body.reason if body is not None else None
    try:
        return await request_store.mark_rejected(request_id, reason=reason)
    except AccessRequestNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
