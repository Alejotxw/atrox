import base64
import os

import pytest

from atrox.security.encryption import (
    DecryptionError,
    EncryptionKeyError,
    EncryptionService,
    decode_master_key,
    generate_master_key,
    get_encryption_service,
)
from atrox.security.sensitive_fields import SensitiveFieldEncryptor


@pytest.fixture
def master_key_b64() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


@pytest.fixture
def encryption_service(master_key_b64: str) -> EncryptionService:
    return get_encryption_service(master_key_b64)


@pytest.fixture
def other_key_service() -> EncryptionService:
    other_key = base64.b64encode(os.urandom(32)).decode("ascii")
    return get_encryption_service(other_key)


def test_encrypt_decrypt_roundtrip(encryption_service: EncryptionService) -> None:
    plaintext = "SQL Injection evidence: ' OR 1=1 --"

    blob = encryption_service.encrypt(plaintext)
    decrypted = encryption_service.decrypt(blob)

    assert decrypted == plaintext
    assert blob.algorithm == "AES-256-GCM"
    assert blob.payload != plaintext


def test_encrypted_blob_is_not_readable_without_key(
    encryption_service: EncryptionService,
    other_key_service: EncryptionService,
) -> None:
    blob = encryption_service.encrypt_to_dict("credencial-secreta: admin/P@ssw0rd")

    assert "credencial-secreta" not in blob["payload"]

    with pytest.raises(DecryptionError, match="llave incorrecta"):
        other_key_service.decrypt_from_dict(blob)


def test_tampered_ciphertext_fails_decryption(
    encryption_service: EncryptionService,
) -> None:
    blob = encryption_service.encrypt_to_dict("hallazgo sensible")

    tampered = dict(blob)
    payload_bytes = bytearray(base64.b64decode(tampered["payload"]))
    payload_bytes[-1] ^= 0xFF
    tampered["payload"] = base64.b64encode(payload_bytes).decode("ascii")

    with pytest.raises(DecryptionError):
        encryption_service.decrypt_from_dict(tampered)


def test_missing_master_key_raises() -> None:
    with pytest.raises(EncryptionKeyError, match="no está configurada"):
        decode_master_key("")


def test_invalid_master_key_length_raises() -> None:
    short_key = base64.b64encode(b"too-short").decode("ascii")

    with pytest.raises(EncryptionKeyError, match="32 bytes"):
        decode_master_key(short_key)


def test_decode_accepts_hex_encoded_key() -> None:
    raw_key = os.urandom(32)
    hex_key = raw_key.hex()

    assert decode_master_key(hex_key) == raw_key


def test_generate_master_key_produces_valid_key() -> None:
    generated = generate_master_key()
    decoded = decode_master_key(generated)

    assert len(decoded) == 32


def test_sensitive_field_encryptor_finding(encryption_service: EncryptionService) -> None:
    encryptor = SensitiveFieldEncryptor(encryption_service)

    finding = {
        "id": "VULN-001",
        "severity": "critical",
        "evidence": "POST /login.php parameter 'user' injectable",
        "poc": "' OR 1=1 --",
    }

    encrypted = encryptor.encrypt_fields("finding", finding)

    assert encrypted["id"] == "VULN-001"
    assert encryptor.is_encrypted(encrypted["evidence"])
    assert "injectable" not in str(encrypted["evidence"])

    decrypted = encryptor.decrypt_fields("finding", encrypted)
    assert decrypted["evidence"] == finding["evidence"]
    assert decrypted["poc"] == finding["poc"]


def test_sensitive_field_encryptor_report(encryption_service: EncryptionService) -> None:
    encryptor = SensitiveFieldEncryptor(encryption_service)

    report = {
        "title": "Auditoría Q2",
        "content": "Resumen confidencial con credenciales expuestas.",
    }

    encrypted = encryptor.encrypt_fields("report", report)
    assert encryptor.is_encrypted(encrypted["content"])
    assert "confidencial" not in str(encrypted["content"])


def test_sensitive_field_encryptor_credential(encryption_service: EncryptionService) -> None:
    encryptor = SensitiveFieldEncryptor(encryption_service)

    credential = {
        "username": "admin",
        "password": "SuperSecret123!",
        "host": "10.0.0.5",
    }

    encrypted = encryptor.encrypt_fields("credential", credential)

    assert encrypted["username"] == "admin"
    assert encryptor.is_encrypted(encrypted["password"])
    assert "SuperSecret" not in str(encrypted["password"])


def test_get_encryption_service_from_settings_requires_env(monkeypatch) -> None:
    monkeypatch.delenv("ATROX_ENCRYPTION_MASTER_KEY", raising=False)

    from atrox.config import get_settings
    from atrox.security.deps import get_encryption_service_from_settings

    get_settings.cache_clear()
    get_encryption_service_from_settings.cache_clear()

    with pytest.raises(EncryptionKeyError, match="no está configurada"):
        get_encryption_service_from_settings()

    get_settings.cache_clear()
    get_encryption_service_from_settings.cache_clear()
