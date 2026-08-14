"""Hashing de contraseñas de cuentas de usuario (HU super-admin).

Usa `hashlib.scrypt` (stdlib, sin dependencias nuevas) en vez de un hash
reversible — nunca se persiste la contraseña en claro, solo el hash con su
salt. No usa `SensitiveFieldEncryptor` (AES-256-GCM es reversible; para
contraseñas se requiere un hash de una sola vía).
"""

import base64
import binascii
import hashlib
import hmac
import os
import secrets

_SALT_LENGTH_BYTES = 16
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LENGTH_BYTES = 32


def hash_password(password: str) -> str:
    """Genera `scrypt$<salt_b64>$<hash_b64>` a partir de la contraseña en claro."""
    salt = os.urandom(_SALT_LENGTH_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_KEY_LENGTH_BYTES
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(derived).decode("ascii")
    return f"scrypt${salt_b64}${hash_b64}"


def verify_password(password: str, hashed: str) -> bool:
    """Verifica una contraseña en claro contra un hash generado por `hash_password`."""
    try:
        scheme, salt_b64, hash_b64 = hashed.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False

    try:
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, binascii.Error):
        return False

    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=len(expected)
    )
    return hmac.compare_digest(derived, expected)


def generate_temporary_password() -> str:
    """Genera una contraseña temporal legible para mostrar una sola vez al admin."""
    return secrets.token_urlsafe(9)
