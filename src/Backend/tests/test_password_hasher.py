"""Tests unitarios del hashing de contraseñas de cuentas (scrypt, stdlib)."""

from atrox.security.password_hasher import generate_temporary_password, hash_password, verify_password


class TestHashPassword:
    def test_verify_succeeds_with_correct_password(self) -> None:
        hashed = hash_password("CorrectHorseBattery1!")
        assert verify_password("CorrectHorseBattery1!", hashed) is True

    def test_verify_fails_with_wrong_password(self) -> None:
        hashed = hash_password("CorrectHorseBattery1!")
        assert verify_password("WrongPassword", hashed) is False

    def test_hash_never_contains_plaintext(self) -> None:
        hashed = hash_password("CorrectHorseBattery1!")
        assert "CorrectHorseBattery1!" not in hashed

    def test_two_hashes_of_same_password_differ_by_salt(self) -> None:
        hashed1 = hash_password("same-password")
        hashed2 = hash_password("same-password")
        assert hashed1 != hashed2
        assert verify_password("same-password", hashed1) is True
        assert verify_password("same-password", hashed2) is True

    def test_verify_rejects_malformed_hash(self) -> None:
        assert verify_password("anything", "not-a-valid-hash") is False


class TestGenerateTemporaryPassword:
    def test_generates_nonempty_random_string(self) -> None:
        pw1 = generate_temporary_password()
        pw2 = generate_temporary_password()
        assert len(pw1) >= 8
        assert pw1 != pw2
