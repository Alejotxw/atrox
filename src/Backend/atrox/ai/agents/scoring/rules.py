"""Heurísticas de scoring de confianza para descartar falsos positivos (HU-016 / RF-005).

Catálogo de señales transparentes y explicables (sin LLM conectado — ver
`docs/ai/HU-016-scoring-evaluation.md`), en el mismo espíritu que
`atrox/ai/agents/vectors/correlator.py`.
"""

from atrox.scanner.models import VulnFinding, VulnSeverity

# Score base por severidad reportada por Nuclei.
BASE_SCORE_BY_SEVERITY: dict[VulnSeverity, int] = {
    VulnSeverity.CRITICAL: 70,
    VulnSeverity.HIGH: 60,
    VulnSeverity.MEDIUM: 50,
    VulnSeverity.LOW: 35,
    VulnSeverity.INFO: 20,
    VulnSeverity.UNKNOWN: 30,
}
DEFAULT_BASE_SCORE = 30

# Tags de plantillas que suelen ser fingerprinting/informativas, no
# confirmación de una vulnerabilidad explotable.
FINGERPRINT_TAGS = {"tech", "fingerprint", "detect", "panel", "ssl", "tls"}

EVIDENCE_BONUS = 15
CVE_BONUS = 10
REFERENCE_BONUS_PER_ITEM = 5
REFERENCE_BONUS_CAP = 15
FINGERPRINT_PENALTY = 20
NO_DESCRIPTION_PENALTY = 10


def score_finding(finding: VulnFinding) -> tuple[int, list[str]]:
    """Calcula un score 0-100 y la lista de razones (heurísticas) que lo componen."""
    reasons: list[str] = []

    base = BASE_SCORE_BY_SEVERITY.get(finding.severity, DEFAULT_BASE_SCORE)
    score = base
    reasons.append(f"severidad {finding.severity.value} (base {base})")

    if finding.extracted_results:
        score += EVIDENCE_BONUS
        reasons.append(f"evidencia extraída presente (+{EVIDENCE_BONUS})")

    tags_lower = {tag.lower() for tag in finding.tags}
    has_cve = "cve" in tags_lower or "cve" in finding.template_id.lower()
    if has_cve:
        score += CVE_BONUS
        reasons.append(f"CVE asociado (+{CVE_BONUS})")

    if finding.references:
        ref_bonus = min(REFERENCE_BONUS_CAP, REFERENCE_BONUS_PER_ITEM * len(finding.references))
        score += ref_bonus
        reasons.append(f"{len(finding.references)} referencia(s) externa(s) (+{ref_bonus})")

    fingerprint_hits = tags_lower & FINGERPRINT_TAGS
    if fingerprint_hits:
        score -= FINGERPRINT_PENALTY
        reasons.append(
            f"tags de fingerprinting/informativos {sorted(fingerprint_hits)} (-{FINGERPRINT_PENALTY})"
        )

    if not finding.description.strip():
        score -= NO_DESCRIPTION_PENALTY
        reasons.append(f"sin descripción de contexto (-{NO_DESCRIPTION_PENALTY})")

    score = max(0, min(100, score))
    return score, reasons
