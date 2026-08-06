"""Muestras de respuestas de la API NVD CVE 2.0 (HU-005)."""


def nvd_vulnerability(
    cve_id: str,
    *,
    published: str = "2021-12-10T10:15:06.250",
    last_modified: str = "2023-09-08T08:56:52.467",
    description: str = "Descripción de prueba",
    base_score: float | None = 10.0,
    base_severity: str | None = "CRITICAL",
    vector: str | None = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
) -> dict:
    """Construye un ítem `{cve: {...}}` como el que devuelve NVD."""
    metrics: dict = {}
    if base_score is not None:
        metrics["cvssMetricV31"] = [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "baseScore": base_score,
                    "baseSeverity": base_severity,
                    "vectorString": vector,
                },
            }
        ]
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": last_modified,
            "descriptions": [
                {"lang": "en", "value": description},
                {"lang": "es", "value": "Descripción en español"},
            ],
            "metrics": metrics,
        }
    }


def nvd_page(vulnerabilities: list[dict], *, start_index: int = 0) -> dict:
    """Construye una página de respuesta de la API NVD."""
    return {
        "resultsPerPage": len(vulnerabilities),
        "startIndex": start_index,
        "totalResults": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }
