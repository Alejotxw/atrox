"""Fakes de la API NVD para tests unitarios (HU-005)."""

from datetime import datetime

from atrox.threat_intel.models import CVEEntry


class FakeNvdClient:
    """Cliente NVD fake: devuelve un lote fijo o lanza un error de red."""

    def __init__(
        self,
        entries: list[CVEEntry] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.entries = entries or []
        self.error = error
        self.last_since: datetime | None = None

    async def fetch_changes(self, since: datetime | None = None) -> list[CVEEntry]:
        self.last_since = since
        if self.error is not None:
            raise self.error
        return self.entries


class FakeHttpClient:
    """Emula httpx.AsyncClient.get registrando params por página."""

    def __init__(self, pages: list[dict]) -> None:
        self.pages = pages
        self.requested_params: list[dict] = []

    async def get(self, url: str, params: dict, headers: dict):
        self.requested_params.append(params)
        page = self.pages[min(len(self.requested_params) - 1, len(self.pages) - 1)]
        return FakeResponse(200, page)


class FakeResponse:
    """Respuesta HTTP mínima que emula httpx.Response."""

    def __init__(self, status_code: int, payload: dict | None = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text or str(payload)

    def json(self) -> dict:
        if self._payload is None:
            raise ValueError("No JSON")
        return self._payload
