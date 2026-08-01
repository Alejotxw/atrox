"""Tests unitarios para configuracion de la cola de trabajos (HU-004)."""

from atrox.config import Settings


class TestQueueConfigDefaults:
    """Scenario: Config fields have correct defaults (spec requirement)."""

    def test_max_concurrent_scans_default_is_10(self) -> None:
        settings = Settings()
        assert settings.max_concurrent_scans == 10

    def test_queue_max_size_default_is_50(self) -> None:
        settings = Settings()
        assert settings.queue_max_size == 50

    def test_parse_workers_default_is_2(self) -> None:
        settings = Settings()
        assert settings.parse_workers == 2


class TestQueueConfigCustomValues:
    """Scenario: Custom configuration via env (spec requirement)."""

    def test_custom_max_concurrent_scans(self, monkeypatch) -> None:
        monkeypatch.setenv("ATROX_MAX_CONCURRENT_SCANS", "5")
        settings = Settings()
        assert settings.max_concurrent_scans == 5

    def test_custom_queue_max_size(self, monkeypatch) -> None:
        monkeypatch.setenv("ATROX_QUEUE_MAX_SIZE", "100")
        settings = Settings()
        assert settings.queue_max_size == 100

    def test_custom_parse_workers(self, monkeypatch) -> None:
        monkeypatch.setenv("ATROX_PARSE_WORKERS", "4")
        settings = Settings()
        assert settings.parse_workers == 4
