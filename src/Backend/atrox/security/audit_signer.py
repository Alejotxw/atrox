import base64
import binascii
import hashlib
import hmac
import json
from typing import Any

SIGNATURE_ALGORITHM = "HMAC-SHA256"
MIN_KEY_LENGTH = 32


class AuditSigningKeyError(ValueError):
    """Error de configuración de la llave de firma de auditoría."""


class AuditSignatureError(ValueError):
    """Firma inválida o entrada alterada."""


def decode_signing_key(raw_key: str) -> bytes:
    value = raw_key.strip()
    if not value:
        raise AuditSigningKeyError(
            "ATROX_AUDIT_SIGNING_KEY no está configurada. "
            "Inyéctela únicamente vía variable de entorno en el despliegue."
        )

    key: bytes | None = None

    try:
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) >= MIN_KEY_LENGTH:
            key = decoded
    except binascii.Error:
        pass

    if key is None:
        try:
            decoded = bytes.fromhex(value)
            if len(decoded) >= MIN_KEY_LENGTH:
                key = decoded
        except ValueError:
            pass

    if key is None:
        raise AuditSigningKeyError(
            f"La llave de firma debe tener al menos {MIN_KEY_LENGTH} bytes (base64 o hex)."
        )

    return key


def generate_signing_key() -> str:
    import os

    return base64.b64encode(os.urandom(32)).decode("ascii")


def canonical_payload(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


class AuditSigner:
    """Firma y verifica entradas del log de auditoría con HMAC-SHA256."""

    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < MIN_KEY_LENGTH:
            raise AuditSigningKeyError(
                f"Se requieren al menos {MIN_KEY_LENGTH} bytes para la llave de firma."
            )
        self._key = signing_key

    def sign(self, payload: dict[str, Any]) -> str:
        signing_body = {k: v for k, v in payload.items() if k != "signature"}
        digest = hmac.new(
            self._key,
            canonical_payload(signing_body),
            hashlib.sha256,
        ).digest()
        return base64.b64encode(digest).decode("ascii")

    def verify(self, entry: dict[str, Any]) -> bool:
        signature = entry.get("signature")
        if not signature or not isinstance(signature, str):
            return False

        expected = self.sign(entry)
        return hmac.compare_digest(expected, signature)

    def verify_or_raise(self, entry: dict[str, Any]) -> None:
        if not self.verify(entry):
            raise AuditSignatureError(
                f"Entrada de auditoría alterada o firma inválida (id={entry.get('id')})"
            )
