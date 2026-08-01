from functools import lru_cache

from atrox.config import get_settings
from atrox.security.encryption import EncryptionKeyError, EncryptionService, get_encryption_service


@lru_cache
def get_encryption_service_from_settings() -> EncryptionService:
    """Obtiene el servicio de cifrado usando ATROX_ENCRYPTION_MASTER_KEY."""
    settings = get_settings()
    if not settings.encryption_master_key:
        raise EncryptionKeyError(
            "ATROX_ENCRYPTION_MASTER_KEY no está configurada. "
            "Inyéctela únicamente vía variable de entorno en el despliegue."
        )
    return get_encryption_service(settings.encryption_master_key)
