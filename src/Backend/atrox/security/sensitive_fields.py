from typing import Any

from atrox.security.encryption import EncryptionService

# Campos sensibles por categoría de entidad (reportes, credenciales, hallazgos).
SENSITIVE_FIELDS: dict[str, frozenset[str]] = {
    "finding": frozenset({"evidence", "poc", "raw_output", "description"}),
    "credential": frozenset({"password", "secret", "token", "private_key"}),
    "report": frozenset({"content", "executive_summary", "business_impact_narrative", "technical_details", "body"}),
}


class SensitiveFieldEncryptor:
    """Cifra y descifra campos sensibles antes de persistir en repositorio/BD."""

    def __init__(self, encryption: EncryptionService) -> None:
        self._encryption = encryption

    def encrypt_fields(self, category: str, data: dict[str, Any]) -> dict[str, Any]:
        fields = SENSITIVE_FIELDS.get(category)
        if not fields:
            raise ValueError(f"Categoría de datos sensibles desconocida: {category}")

        result = dict(data)
        for field_name in fields:
            if field_name not in result or result[field_name] is None:
                continue

            value = result[field_name]
            if isinstance(value, dict) and "payload" in value and "alg" in value:
                continue

            if not isinstance(value, str):
                value = str(value)

            result[field_name] = self._encryption.encrypt_to_dict(value)

        return result

    def decrypt_fields(self, category: str, data: dict[str, Any]) -> dict[str, Any]:
        fields = SENSITIVE_FIELDS.get(category)
        if not fields:
            raise ValueError(f"Categoría de datos sensibles desconocida: {category}")

        result = dict(data)
        for field_name in fields:
            if field_name not in result or result[field_name] is None:
                continue

            encrypted = result[field_name]
            if isinstance(encrypted, dict):
                result[field_name] = self._encryption.decrypt_from_dict(encrypted)

        return result

    @staticmethod
    def is_encrypted(value: Any) -> bool:
        return (
            isinstance(value, dict)
            and value.get("alg") == "AES-256-GCM"
            and "payload" in value
        )
