from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from atrox.config import get_settings
from atrox.security.auth_deps import get_mfa_service, require_mfa_admin
from atrox.security.mfa_service import MfaService, generate_otpauth_url

router = APIRouter(prefix="/api/auth", tags=["Autenticación MFA"])


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
):
    """Paso 1 de la autenticación: verificación de usuario y contraseña."""
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
):
    """Retorna el estado de la sesión actual autenticada mediante MFA."""
    return session_info


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
