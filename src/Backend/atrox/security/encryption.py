import base64
import binascii
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITHM = "AES-256-GCM"
KEY_LENGTH_BYTES = 32
NONCE_LENGTH_BYTES = 12
PAYLOAD_VERSION = 1


class EncryptionKeyError(ValueError):
    """Error de configuración o formato de la llave maestra."""


class DecryptionError(ValueError):
    """Error al descifrar: llave incorrecta, datos alterados o formato inválido."""


@dataclass(frozen=True)
class EncryptedBlob:
    """Representación estructurada de un valor cifrado en reposo."""

    version: int
    algorithm: str
    payload: str

    def to_dict(self) -> dict[str, str | int]:
        return {
            "v": self.version,
            "alg": self.algorithm,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedBlob":
        try:
            return cls(
                version=int(data["v"]),
                algorithm=str(data["alg"]),
                payload=str(data["payload"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DecryptionError("Formato de blob cifrado inválido") from exc


def decode_master_key(raw_key: str) -> bytes:
    """Decodifica la llave maestra desde base64 o hexadecimal (32 bytes)."""
    value = raw_key.strip()
    if not value:
        raise EncryptionKeyError(
            "ATROX_ENCRYPTION_MASTER_KEY no está configurada. "
            "Inyéctela únicamente vía variable de entorno en el despliegue."
        )

    key: bytes | None = None

    try:
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) == KEY_LENGTH_BYTES:
            key = decoded
    except binascii.Error:
        pass

    if key is None:
        try:
            decoded = bytes.fromhex(value)
            if len(decoded) == KEY_LENGTH_BYTES:
                key = decoded
        except ValueError:
            pass

    if key is None or len(key) != KEY_LENGTH_BYTES:
        raise EncryptionKeyError(
            f"La llave maestra debe ser {KEY_LENGTH_BYTES} bytes "
            f"(256 bits) codificados en base64 o hex."
        )

    return key


def generate_master_key() -> str:
    """Genera una llave maestra aleatoria codificada en base64 (solo uso operativo)."""
    return base64.b64encode(os.urandom(KEY_LENGTH_BYTES)).decode("ascii")


class EncryptionService:
    """Servicio de cifrado simétrico AES-256-GCM para datos en reposo."""

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != KEY_LENGTH_BYTES:
            raise EncryptionKeyError(
                f"Se requieren exactamente {KEY_LENGTH_BYTES} bytes para AES-256."
            )
        self._aesgcm = AESGCM(master_key)

    def encrypt(self, plaintext: str | bytes) -> EncryptedBlob:
        data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
        nonce = os.urandom(NONCE_LENGTH_BYTES)
        ciphertext = self._aesgcm.encrypt(nonce, data, None)
        encoded = base64.b64encode(nonce + ciphertext).decode("ascii")

        return EncryptedBlob(
            version=PAYLOAD_VERSION,
            algorithm=ALGORITHM,
            payload=encoded,
        )

    def decrypt(self, blob: EncryptedBlob | dict) -> str:
        if isinstance(blob, dict):
            blob = EncryptedBlob.from_dict(blob)

        if blob.algorithm != ALGORITHM:
            raise DecryptionError(f"Algoritmo no soportado: {blob.algorithm}")
        if blob.version != PAYLOAD_VERSION:
            raise DecryptionError(f"Versión de payload no soportada: {blob.version}")

        try:
            raw = base64.b64decode(blob.payload, validate=True)
        except binascii.Error as exc:
            raise DecryptionError("Payload cifrado corrupto o inválido") from exc

        if len(raw) < NONCE_LENGTH_BYTES + 1:
            raise DecryptionError("Payload cifrado demasiado corto")

        nonce = raw[:NONCE_LENGTH_BYTES]
        ciphertext = raw[NONCE_LENGTH_BYTES:]

        try:
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise DecryptionError(
                "No se pudo descifrar: llave incorrecta o datos alterados"
            ) from exc

        return plaintext.decode("utf-8")

    def encrypt_to_dict(self, plaintext: str) -> dict[str, str | int]:
        return self.encrypt(plaintext).to_dict()

    def decrypt_from_dict(self, data: dict) -> str:
        return self.decrypt(data)


def get_encryption_service(master_key: str) -> EncryptionService:
    """Factory que construye el servicio a partir de la llave en variable de entorno."""
    return EncryptionService(decode_master_key(master_key))
