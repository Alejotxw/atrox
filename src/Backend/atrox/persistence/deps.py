from functools import lru_cache
from pathlib import Path

from fastapi import HTTPException, Request

from atrox.config import get_settings
from atrox.persistence.service import EncryptedPersistenceService
from atrox.persistence.store import JsonEntityStore
from atrox.security.encryption import EncryptionKeyError, get_encryption_service
from atrox.security.sensitive_fields import SensitiveFieldEncryptor


def build_persistence_service() -> EncryptedPersistenceService:
    settings = get_settings()
    if not settings.encryption_master_key:
        raise EncryptionKeyError(
            "ATROX_ENCRYPTION_MASTER_KEY no está configurada. "
            "Requerida para persistir hallazgos, credenciales y reportes cifrados."
        )

    encryptor = SensitiveFieldEncryptor(
        get_encryption_service(settings.encryption_master_key)
    )
    base = Path(settings.encrypted_storage_path)
    return EncryptedPersistenceService(
        encryptor=encryptor,
        findings_store=JsonEntityStore(base / "findings.jsonl"),
        credentials_store=JsonEntityStore(base / "credentials.jsonl"),
        reports_store=JsonEntityStore(base / "reports.jsonl"),
    )


@lru_cache
def get_persistence_service_cached() -> EncryptedPersistenceService:
    return build_persistence_service()


def get_persistence(request: Request) -> EncryptedPersistenceService:
    service = getattr(request.app.state, "persistence", None)
    if service is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Persistencia cifrada no disponible. "
                "Configure ATROX_ENCRYPTION_MASTER_KEY."
            ),
        )
    return service


def get_encryptor_from_request(request: Request) -> SensitiveFieldEncryptor:
    persistence = get_persistence(request)
    return persistence._encryptor  # noqa: SLF001
