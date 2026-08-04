import time
import pytest
from fastapi.testclient import TestClient
from atrox.main import app
from atrox.security.mfa_service import MfaService, generate_totp_secret, generate_totp_code, verify_totp_code

client = TestClient(app)


def test_totp_generation_and_verification():
    secret = generate_totp_secret()
    assert len(secret) == 32
    
    code = generate_totp_code(secret)
    assert len(code) == 6
    assert code.isdigit()
    
    assert verify_totp_code(secret, code) is True
    assert verify_totp_code(secret, "000000") is False


def test_mfa_service_session_and_lockout():
    service = MfaService(
        admin_username="sysadmin",
        admin_password="AtroxAdmin2026!",
        totp_secret=generate_totp_secret(),
        session_ttl_minutes=60,
        max_failed_attempts=3,
        lockout_minutes=15,
    )
    
    # Intento de login con clave errónea
    success, res, token_or_err = service.authenticate_primary("sysadmin", "WrongPassword")
    assert success is False
    assert token_or_err == "Credenciales inválidas"
    assert service.get_failed_attempts("sysadmin") == 1
    
    # 2da clave errónea
    service.authenticate_primary("sysadmin", "WrongPassword")
    assert service.get_failed_attempts("sysadmin") == 2
    
    # 3ra clave errónea -> Dispara bloqueo
    success, res, err = service.authenticate_primary("sysadmin", "WrongPassword")
    assert success is False
    locked, rem = service.is_locked_out("sysadmin")
    assert locked is True
    assert rem > 0
    
    # Intentar con clave correcta estando bloqueado
    success, locked, err = service.authenticate_primary("sysadmin", "AtroxAdmin2026!")
    assert success is False
    assert locked is True
    assert "Cuenta bloqueada" in err


def test_full_auth_api_flow():
    test_secret = generate_totp_secret()
    app.state.mfa_service = MfaService(
        admin_username="sysadmin",
        admin_password="AtroxAdmin2026!",
        totp_secret=test_secret,
        session_ttl_minutes=60,
        max_failed_attempts=5,
        lockout_minutes=15,
    )

    class DummyAuditLog:
        async def query(self, **kwargs):
            return [], True, False
        async def record(self, **kwargs):
            pass

    app.state.audit_log = DummyAuditLog()
    
    # 1. Login primario fallido
    res_bad = client.post("/api/auth/login", json={"username": "sysadmin", "password": "wrong"})
    assert res_bad.status_code == 401
    
    # 2. Login primario exitoso
    res_step1 = client.post("/api/auth/login", json={"username": "sysadmin", "password": "AtroxAdmin2026!"})
    assert res_step1.status_code == 200
    data1 = res_step1.json()
    assert data1["mfa_required"] is True
    mfa_token = data1["mfa_token"]
    assert mfa_token is not None
    
    # 3. Verificación MFA fallida (código erróneo)
    res_mfa_bad = client.post("/api/auth/mfa/verify", json={"mfa_token": mfa_token, "code": "000000"})
    assert res_mfa_bad.status_code == 401
    
    # 4. Verificación MFA exitosa
    valid_code = generate_totp_code(test_secret)
    res_mfa_ok = client.post("/api/auth/mfa/verify", json={"mfa_token": mfa_token, "code": valid_code})
    assert res_mfa_ok.status_code == 200
    data2 = res_mfa_ok.json()
    assert "session_token" in data2
    session_token = data2["session_token"]
    
    # 5. Consultar estado de sesión GET /api/auth/me
    headers = {"Authorization": f"Bearer {session_token}"}
    res_me = client.get("/api/auth/me", headers=headers)
    assert res_me.status_code == 200
    assert res_me.json()["username"] == "sysadmin"
    
    # 6. Probar endpoint protegido de auditoría /api/audit/logs
    res_audit = client.get("/api/audit/logs", headers=headers)
    assert res_audit.status_code == 200
    
    # Sin header o con token inválido -> 401
    res_unauth = client.get("/api/audit/logs")
    assert res_unauth.status_code == 401
    
    # 7. Logout
    res_logout = client.post("/api/auth/logout", headers=headers)
    assert res_logout.status_code == 200
    
    # Tras logout, /api/auth/me falla con 401
    res_me_expired = client.get("/api/auth/me", headers=headers)
    assert res_me_expired.status_code == 401

    app.state.audit_log = None


def test_mfa_setup_endpoint():
    res = client.get("/api/auth/mfa/setup")
    assert res.status_code == 200
    data = res.json()
    assert "secret" in data
    assert "otpauth_url" in data
    assert data["otpauth_url"].startswith("otpauth://totp/")
