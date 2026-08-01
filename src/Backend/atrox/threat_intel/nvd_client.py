"""Cliente asíncrono para la API NVD CVE 2.0 (HU-005 / RF-010).

Descarga y parsea CVEs nuevos/modificados usando el filtro
`lastModStartDate`. Errores de red se propagan como `NvdClientError` para
que el servicio de sincronización los registre sin interrumpir la cola de
escaneos activos.
"""

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from atrox.threat_intel.models import CVEEntry

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000


class NvdClientError(Exception):
    """Error de red, HTTP o formato al comunicarse con la API NVD."""


# -- Parseo de la respuesta NVD 2.0 ------------------------------------------


def _parse_nvd_datetime(value: str | None) -> datetime | None:
    """Parsea fechas NVD (ISO 8601 con/sin 'Z' y con/sin fracción de segundo)."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        logger.warning("Fecha NVD no parseable: %r", value)
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _best_description(descriptions: list[dict[str, Any]]) -> str:
    """Retorna la descripción en inglés (o la primera disponible)."""
    if not descriptions:
        return ""
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")
    return str(descriptions[0].get("value", ""))


_CVSS_METRICS_PREFERENCE = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _best_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """Elige el score CVSS más representativo (V3.1 > V3.0 > V2)."""
    candidates: list[tuple[float, str | None, str | None]] = []
    for metric_key in _CVSS_METRICS_PREFERENCE:
        for metric in metrics.get(metric_key) or []:
            cvss_data = metric.get("cvssData", {})
            try:
                score = float(cvss_data.get("baseScore"))
            except (TypeError, ValueError):
                continue
            candidates.append(
                (
                    score,
                    cvss_data.get("baseSeverity"),
                    cvss_data.get("vectorString"),
                )
            )
    if not candidates:
        return None, None, None
    score, severity, vector = max(candidates, key=lambda item: item[0])
    return score, severity, vector


def parse_nvd_vulnerability(payload: dict[str, Any]) -> CVEEntry:
    """Traduce un ítem `{cve: {...}}` de la API NVD a un `CVEEntry`."""
    cve = payload.get("cve", {})
    cve_id = str(cve.get("id", "")).strip()
    if not cve_id:
        raise NvdClientError("Ítem NVD sin campo cve.id")

    published = _parse_nvd_datetime(cve.get("published"))
    if published is None:
        raise NvdClientError(f"CVE {cve_id} sin fecha de publicación válida")

    score, severity, vector = _best_cvss(cve.get("metrics", {}) or {})

    return CVEEntry(
        cve_id=cve_id,
        description=_best_description(cve.get("descriptions", []) or []),
        cvss_score=score,
        cvss_severity=severity,
        cvss_vector=vector,
        published_date=published,
        last_modified_date=_parse_nvd_datetime(cve.get("lastModified")),
    )


# -- Cliente HTTP -------------------------------------------------------------


class NvdClient:
    """Cliente HTTP asíncrono contra el endpoint de CVEs de NVD.

    `http_client` es inyectable (mismo patrón que `NmapWrapper.runner`)
    para poder mockear la red en tests unitarios.
    """

    def __init__(
        self,
        api_url: str = NVD_API_URL,
        api_key: str | None = None,
        timeout_seconds: int = 30,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_url = api_url
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self._http_client = http_client

    async def fetch_changes(self, since: datetime | None = None) -> list[CVEEntry]:
        """Descarga CVEs nuevos/modificados desde `since` (todo si es None).

        Recorre la paginación de NVD (2000 resultados por página) hasta
        cubrir `totalResults`.
        """
        entries: list[CVEEntry] = []
        start_index = 0
        while True:
            data = await self._fetch_page(start_index=start_index, since=since)
            vulnerabilities = data.get("vulnerabilities", []) or []
            for item in vulnerabilities:
                try:
                    entries.append(parse_nvd_vulnerability(item))
                except NvdClientError:
                    # Un ítem malformado no debe abortar toda la sincronización
                    logger.warning("Ítem NVD malformado omitido: %s", item.get("cve", {}).get("id"))
                    continue

            total = int(data.get("totalResults", 0))
            start_index += RESULTS_PER_PAGE
            if not vulnerabilities or start_index >= total:
                break

        logger.info("NVD devolvió %d CVEs desde %s", len(entries), since or "el inicio")
        return entries

    async def _fetch_page(
        self,
        start_index: int,
        since: datetime | None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
        }
        if since is not None:
            params["lastModStartDate"] = since.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["lastModEndDate"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            )

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        client = self._http_client
        if client is None:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as owned_client:
                return await self._request(owned_client, params, headers)
        return await self._request(client, params, headers)

    async def _request(
        self,
        client: httpx.AsyncClient,
        params: dict[str, Any],
        headers: dict[str, str],
    ) -> dict[str, Any]:
        try:
            response = await client.get(self.api_url, params=params, headers=headers)
        except (httpx.HTTPError, OSError) as exc:
            raise NvdClientError(f"Error de red al consultar NVD: {exc}") from exc

        if response.status_code == 429 or response.status_code >= 500:
            raise NvdClientError(
                f"NVD respondió {response.status_code} (rate limit o error del servicio)"
            )
        if response.status_code != 200:
            raise NvdClientError(
                f"NVD respondió HTTP {response.status_code}: {response.text[:200]}"
            )

        try:
            return response.json()
        except ValueError as exc:
            raise NvdClientError("NVD devolvió una respuesta JSON inválida") from exc
