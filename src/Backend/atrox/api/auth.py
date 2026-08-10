import asyncio

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from atrox.accounts.models import AccountStatus
from atrox.accounts.store import AccountStore
from atrox.api.accounts import get_account_store
from atrox.config import get_settings
from atrox.security.auth_deps import get_mfa_service, require_mfa_admin
from atrox.security.mfa_service import MfaService, generate_otpauth_url
from atrox.security.password_hasher import hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["Autenticación MFA"])

# Hash "señuelo" fijo (no corresponde a ninguna cuenta real). Se verifica
# contra él cuando el username no existe, para que un intento de login con
# usuario inexistente tarde lo mismo (una pasada de scrypt) que uno con
# usuario real y contraseña incorrecta — sin esto, la ausencia de la
# llamada a scrypt en el caso "no existe" es un canal de tiempo que permite
# enumerar qué usernames de cuentas regulares son válidos.
_DECOY_PASSWORD_HASH = hash_password("decoy-not-a-real-account-password")


class LoginRequest(BaseModel):
    username: str
    password: str


class MfaVerifyRequest(BaseModel):
    mfa_token: str
    code: str


@router.post("/login")
async def login_step1(
    body: LoginRequest,
    mfa_service: MfaService = Depends(get_mfa_service),
    account_store: AccountStore = Depends(get_account_store),
):
    """Paso 1 de la autenticación.

    El sysadmin único (`ATROX_ADMIN_USERNAME`) completa un segundo factor
    TOTP como siempre. Las cuentas regulares — creadas al aprobar una
    solicitud de acceso — inician sesión directamente con usuario y
    contraseña, sin TOTP (no tienen secreto TOTP individual propio).
    """
    if body.username == mfa_service.admin_username:
        success, is_locked, result = mfa_service.authenticate_primary(body.username, body.password)

        if is_locked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=result,
            )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result,
            )

        return {
            "mfa_required": True,
            "mfa_token": result,
            "message": "Credenciales correctas. Ingrese su código TOTP de 6 dígitos para completar el acceso.",
        }

    is_locked, remaining_seconds = mfa_service.is_locked_out(body.username)
    if is_locked:
        minutes = max(1, remaining_seconds // 60)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Cuenta bloqueada por múltiples intentos fallidos. Reintente en {minutes} minuto(s).",
        )

    account = await account_store.get_by_username(body.username)
    # scrypt es CPU-bound (ADR-001: no bloquear el loop async) — se offloadea a
    # un hilo. Se verifica SIEMPRE, incluso si la cuenta no existe (contra un
    # hash señuelo), para no filtrar por tiempo de respuesta qué usernames son
    # válidos.
    password_hash_to_check = account.password_hash if account is not None else _DECOY_PASSWORD_HASH
    password_is_valid = await asyncio.to_thread(verify_password, body.password, password_hash_to_check)

    if account is None or account.status != AccountStatus.ACTIVE or not password_is_valid:
        mfa_service.record_login_failure(body.username)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")

    mfa_service.record_login_success(body.username)
    session_token = mfa_service.create_direct_session(account.username)
    return {
        "mfa_required": False,
        "session_token": session_token,
        "expires_in_minutes": mfa_service.session_ttl_minutes,
        # "role" aquí es el NIVEL DE AUTORIZACIÓN ("SysAdmin"/"Usuario", ver
        # también GET /api/auth/me) — no confundir con `Account.role`, el rol
        # organizacional en texto libre que el solicitante indicó en el
        # formulario (ej. "Estudiante"). Son dos conceptos distintos que
        # comparten nombre de campo por coincidencia con el `role` que ya
        # devolvía /api/auth/mfa/verify antes de este cambio.
        "user": {"username": account.username, "role": "Usuario"},
    }


@router.post("/mfa/verify")
async def verify_mfa_step2(
    body: MfaVerifyRequest,
    mfa_service: MfaService = Depends(get_mfa_service),
):
    """Paso 2 de la autenticación: verificación de token MFA de 6 dígitos."""
    success, is_locked, result = mfa_service.verify_mfa(body.mfa_token, body.code)

    if is_locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=result,
        )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result,
        )

    return {
        "session_token": result,
        "expires_in_minutes": mfa_service.session_ttl_minutes,
        # "role" = nivel de autorización, no el rol organizacional de Account.role — ver login_step1.
        "user": {
            "username": mfa_service.admin_username,
            "role": "SysAdmin",
        },
    }


@router.get("/mfa/setup")
async def get_mfa_setup(
    mfa_service: MfaService = Depends(get_mfa_service),
):
    """Obtiene la clave secreta TOTP y la URI otpauth:// para escanear en apps autenticadoras."""
    settings = get_settings()
    secret = mfa_service.totp_secret
    otpauth_url = generate_otpauth_url(
        secret=secret,
        username=mfa_service.admin_username,
        issuer=settings.app_name,
    )
    return {
        "username": mfa_service.admin_username,
        "secret": secret,
        "otpauth_url": otpauth_url,
    }


@router.get("/me")
async def get_current_user_status(
    session_info: dict = Depends(require_mfa_admin),
    mfa_service: MfaService = Depends(get_mfa_service),
):
    """Retorna el estado de la sesión actual, incluyendo el rol (SysAdmin vs Usuario)

    El frontend usa `role` para decidir si mostrar el panel de Administración —
    la autorización real la sigue aplicando el backend (`require_super_admin`)
    en cada endpoint, esto es solo para no ofrecer una UI que el backend luego
    rechaza con 403.
    """
    role = "SysAdmin" if session_info.get("username") == mfa_service.admin_username else "Usuario"
    return {**session_info, "role": role}


@router.post("/logout")
async def logout(
    session_info: dict = Depends(require_mfa_admin),
    mfa_service: MfaService = Depends(get_mfa_service),
):
    """Cierra la sesión activa del SysAdmin."""
    session_token = session_info.get("session_token")
    if session_token:
        mfa_service.revoke_session(session_token)
    return {"message": "Sesión cerrada exitosamente."}
