import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
import urllib.parse
from datetime import datetime, timedelta, timezone


def generate_totp_secret() -> str:
    """Genera una clave secreta Base32 aleatoria de 160 bits (32 caracteres)."""
    random_bytes = secrets.token_bytes(20)
    return base64.b32encode(random_bytes).decode("utf-8").replace("=", "")


def _get_counter_bytes(time_step: int | None = None) -> bytes:
    if time_step is None:
        time_step = int(time.time()) // 30
    return struct.pack(">Q", time_step)


def generate_totp_code(secret: str, time_step: int | None = None) -> str:
    """Genera un código TOTP de 6 dígitos según RFC 6238 (HMAC-SHA1)."""
    # Padding de base32 si falta
    secret_clean = secret.strip().upper()
    padding_needed = (8 - len(secret_clean) % 8) % 8
    secret_padded = secret_clean + ("=" * padding_needed)
    
    key = base64.b32decode(secret_padded, casefold=True)
    msg = _get_counter_bytes(time_step)
    
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    
    code_int = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    ) % 1_000_000
    
    return f"{code_int:06d}"


def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    """Verifica si el código TOTP es válido considerando una ventana de tolerancia."""
    if not code or not code.isdigit() or len(code) != 6:
        return False
        
    current_time_step = int(time.time()) // 30
    for delta in range(-window, window + 1):
        expected = generate_totp_code(secret, current_time_step + delta)
        if hmac.compare_digest(expected, code.strip()):
            return True
    return False


def generate_otpauth_url(secret: str, username: str, issuer: str = "Atrox Framework") -> str:
    """Genera una URI otpauth:// compatible con Google Authenticator / Authy."""
    label = f"{issuer}:{username}"
    params = {
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": "6",
        "period": "30",
    }
    encoded_label = urllib.parse.quote(label)
    encoded_params = urllib.parse.urlencode(params)
    return f"otpauth://totp/{encoded_label}?{encoded_params}"


class MfaService:
    """Servicio integral de MFA: credenciales, TOTP, sesiones y política de bloqueo."""

    def __init__(
        self,
        admin_username: str = "sysadmin",
        admin_password: str = "AtroxAdmin2026!",
        totp_secret: str | None = None,
        session_ttl_minutes: int = 60,
        max_failed_attempts: int = 5,
        lockout_minutes: int = 15,
    ):
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.totp_secret = totp_secret or generate_totp_secret()
        self.session_ttl_minutes = session_ttl_minutes
        self.max_failed_attempts = max_failed_attempts
        self.lockout_minutes = lockout_minutes

        # Memoria de bloqueo: username -> {"attempts": int, "lockout_until": timestamp | None}
        self._lockout_data: dict[str, dict] = {}
        # Memoria de tokens MFA pendientes: mfa_token -> {"username": str, "expires_at": float}
        self._pending_mfa_tokens: dict[str, dict] = {}
        # Memoria de sesiones activas: session_token -> {"username": str, "expires_at": float, "created_at": float}
        self._active_sessions: dict[str, dict] = {}

    def get_failed_attempts(self, username: str) -> int:
        record = self._lockout_data.get(username, {})
        return record.get("attempts", 0)

    def is_locked_out(self, username: str) -> tuple[bool, int]:
        """Retorna (está_bloqueado, segundos_restantes)."""
        record = self._lockout_data.get(username)
        if not record:
            return False, 0
        
        lockout_until = record.get("lockout_until")
        if lockout_until:
            now = time.time()
            if now < lockout_until:
                return True, int(lockout_until - now)
            else:
                # El tiempo de bloqueo ya expiró
                record["lockout_until"] = None
                record["attempts"] = 0
        return False, 0

    def _record_failure(self, username: str):
        now = time.time()
        record = self._lockout_data.setdefault(username, {"attempts": 0, "lockout_until": None})
        record["attempts"] += 1
        if record["attempts"] >= self.max_failed_attempts:
            record["lockout_until"] = now + (self.lockout_minutes * 60)

    def _record_success(self, username: str):
        if username in self._lockout_data:
            self._lockout_data[username] = {"attempts": 0, "lockout_until": None}

    def record_login_failure(self, username: str) -> None:
        """Registra un intento fallido para cuentas regulares (login sin TOTP)."""
        self._record_failure(username)

    def record_login_success(self, username: str) -> None:
        """Limpia el contador de intentos fallidos tras un login exitoso sin TOTP."""
        self._record_success(username)

    def _create_session(self, username: str) -> str:
        """Crea y registra una sesión activa — único punto que escribe en `_active_sessions`."""
        session_token = f"session_{secrets.token_urlsafe(32)}"
        now = time.time()
        self._active_sessions[session_token] = {
            "username": username,
            "created_at": now,
            "expires_at": now + (self.session_ttl_minutes * 60),
        }
        return session_token

    def create_direct_session(self, username: str) -> str:
        """Crea una sesión activa sin pasar por el segundo factor TOTP.

        Usado por cuentas regulares (creadas al aprobar una solicitud de
        acceso): comparten el mismo pool de sesiones que el sysadmin, así
        `validate_session`/`revoke_session` y todos los endpoints protegidos
        con `require_mfa_admin` funcionan igual sin duplicar lógica.
        """
        return self._create_session(username)

    def authenticate_primary(self, username: str, password: str) -> tuple[bool, bool, str | None]:
        """Paso 1: autenticación de usuario y clave.
        Retorna: (exito, locked_out, mfa_token_o_mensaje_error)
        """
        is_locked, rem_seconds = self.is_locked_out(username)
        if is_locked:
            minutes = max(1, rem_seconds // 60)
            return False, True, f"Cuenta bloqueada por múltiples intentos fallidos. Reintente en {minutes} minuto(s)."

        if username != self.admin_username or password != self.admin_password:
            self._record_failure(username)
            return False, False, "Credenciales inválidas"

        # Éxito en paso 1: emitir mfa_token temporal de 5 min
        mfa_token = f"mfa_{secrets.token_urlsafe(32)}"
        self._pending_mfa_tokens[mfa_token] = {
            "username": username,
            "expires_at": time.time() + 300,
        }
        return True, False, mfa_token

    def verify_mfa(self, mfa_token: str, code: str) -> tuple[bool, bool, str | None]:
        """Paso 2: verificación de TOTP.
        Retorna: (exito, locked_out, session_token_o_mensaje_error)
        """
        pending = self._pending_mfa_tokens.get(mfa_token)
        if not pending or time.time() > pending["expires_at"]:
            return False, False, "Token MFA inválido o expirado"

        username = pending["username"]
        is_locked, rem_seconds = self.is_locked_out(username)
        if is_locked:
            minutes = max(1, rem_seconds // 60)
            return False, True, f"Cuenta bloqueada. Reintente en {minutes} minuto(s)."

        if not verify_totp_code(self.totp_secret, code):
            self._record_failure(username)
            is_now_locked, rem_secs = self.is_locked_out(username)
            if is_now_locked:
                return False, True, f"Código MFA incorrecto. Máximo de intentos alcanzado. Cuenta bloqueada por {self.lockout_minutes} minutos."
            return False, False, f"Código MFA incorrecto. Intentos fallidos: {self.get_failed_attempts(username)}/{self.max_failed_attempts}"

        # Éxito total: eliminar token pendiente y crear sesión final
        del self._pending_mfa_tokens[mfa_token]
        self._record_success(username)

        session_token = self._create_session(username)
        return True, False, session_token

    def validate_session(self, session_token: str) -> dict | None:
        """Valida una sesión activa."""
        if not session_token:
            return None
        
        session = self._active_sessions.get(session_token)
        if not session:
            return None
        
        now = time.time()
        if now > session["expires_at"]:
            del self._active_sessions[session_token]
            return None
        
        return {
            "username": session["username"],
            "expires_at": session["expires_at"],
            "seconds_remaining": int(session["expires_at"] - now),
        }

    def revoke_session(self, session_token: str) -> bool:
        """Cierra la sesión activa."""
        if session_token in self._active_sessions:
            del self._active_sessions[session_token]
            return True
        return False

    def revoke_sessions_for_username(self, username: str) -> int:
        """Revoca todas las sesiones activas de un usuario (ej. al suspender/eliminar su cuenta).

        Sin esto, una cuenta suspendida/eliminada seguiría autenticada con
        una sesión ya emitida hasta que expire por tiempo (`session_ttl_minutes`).
        """
        tokens_to_revoke = [
            token for token, session in self._active_sessions.items() if session["username"] == username
        ]
        for token in tokens_to_revoke:
            del self._active_sessions[token]
        return len(tokens_to_revoke)
