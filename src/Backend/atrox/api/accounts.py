from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status

from atrox.accounts.models import (
    Account,
    AccountListResult,
    AccountPublic,
    AccountStatus,
    ModerationActionRequest,
    ModerationNoteKind,
)
from atrox.accounts.store import AccountNotFoundError, AccountStore
from atrox.config import get_settings
from atrox.security.auth_deps import get_mfa_service, require_super_admin
from atrox.security.mfa_service import MfaService

router = APIRouter(prefix="/api/accounts", tags=["accounts"], dependencies=[Depends(require_super_admin)])


def get_account_store(request: Request) -> AccountStore:
    """Obtiene el AccountStore desde el estado de la aplicación.

    Instancia por defecto si el lifespan no lo configuró (mismo patrón que
    `get_mfa_service` en auth_deps.py) — necesario porque `/api/auth/login`
    depende de este store y muchos tests de auth no ejecutan el lifespan.
    """
    store = getattr(request.app.state, "account_store", None)
    if store is None:
        settings = get_settings()
        store = AccountStore(
            store_path=Path(settings.account_store_path),
            reserved_usernames=frozenset({settings.admin_username}),
        )
        request.app.state.account_store = store
    return store


def account_to_public(account: Account) -> AccountPublic:
    return AccountPublic.model_validate(account.model_dump())


@router.get("", response_model=AccountListResult)
async def list_accounts(store: AccountStore = Depends(get_account_store)) -> AccountListResult:
    """Lista todas las cuentas de usuario (solo administrador)."""
    accounts = await store.list_all()
    return AccountListResult(total=len(accounts), accounts=[account_to_public(a) for a in accounts])


@router.post("/{account_id}/suspend", response_model=AccountPublic)
async def suspend_account(
    account_id: UUID,
    store: AccountStore = Depends(get_account_store),
    mfa_service: MfaService = Depends(get_mfa_service),
) -> AccountPublic:
    """Suspende una cuenta: no podrá iniciar sesión hasta ser reactivada.

    También revoca cualquier sesión ya activa de esa cuenta — de lo
    contrario seguiría autenticada hasta que su sesión expire por tiempo.
    """
    try:
        account = await store.set_status(account_id, AccountStatus.SUSPENDED)
    except AccountNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    mfa_service.revoke_sessions_for_username(account.username)
    return account_to_public(account)


@router.post("/{account_id}/reactivate", response_model=AccountPublic)
async def reactivate_account(
    account_id: UUID, store: AccountStore = Depends(get_account_store)
) -> AccountPublic:
    """Reactiva una cuenta previamente suspendida."""
    try:
        account = await store.set_status(account_id, AccountStatus.ACTIVE)
    except AccountNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return account_to_public(account)


@router.delete("/{account_id}", response_model=AccountPublic)
async def delete_account(
    account_id: UUID,
    store: AccountStore = Depends(get_account_store),
    mfa_service: MfaService = Depends(get_mfa_service),
) -> AccountPublic:
    """Elimina (soft-delete) una cuenta: no podrá iniciar sesión y queda marcada como eliminada.

    También revoca cualquier sesión ya activa de esa cuenta.
    """
    try:
        account = await store.set_status(account_id, AccountStatus.DELETED)
    except AccountNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    mfa_service.revoke_sessions_for_username(account.username)
    return account_to_public(account)


@router.post("/{account_id}/warnings", response_model=AccountPublic, status_code=status.HTTP_201_CREATED)
async def warn_account(
    account_id: UUID,
    body: ModerationActionRequest,
    session_info: dict = Depends(require_super_admin),
    store: AccountStore = Depends(get_account_store),
) -> AccountPublic:
    """Registra una advertencia por uso indebido/fraudulento en el historial de la cuenta."""
    try:
        account = await store.add_moderation_note(
            account_id,
            kind=ModerationNoteKind.WARNING,
            reason=body.reason,
            created_by=session_info.get("username", "sysadmin"),
        )
    except AccountNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return account_to_public(account)


@router.post("/{account_id}/reports", response_model=AccountPublic, status_code=status.HTTP_201_CREATED)
async def report_account(
    account_id: UUID,
    body: ModerationActionRequest,
    session_info: dict = Depends(require_super_admin),
    store: AccountStore = Depends(get_account_store),
) -> AccountPublic:
    """Registra un reporte por uso fraudulento en el historial de la cuenta."""
    try:
        account = await store.add_moderation_note(
            account_id,
            kind=ModerationNoteKind.REPORT,
            reason=body.reason,
            created_by=session_info.get("username", "sysadmin"),
        )
    except AccountNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return account_to_public(account)
