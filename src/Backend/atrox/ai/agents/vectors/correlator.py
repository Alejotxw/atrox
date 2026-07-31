"""Correlación heurística de hallazgos en cadenas de ataque (HU-014)."""

from atrox.ai.agents.vectors.models import AttackVector
from atrox.scanner.models import VulnFinding, VulnSeverity

SEVERITY_WEIGHT: dict[VulnSeverity, float] = {
    VulnSeverity.CRITICAL: 10.0,
    VulnSeverity.HIGH: 7.5,
    VulnSeverity.MEDIUM: 5.0,
    VulnSeverity.LOW: 2.5,
    VulnSeverity.INFO: 1.0,
    VulnSeverity.UNKNOWN: 3.0,
}

# Reglas de encadenamiento: (trigger_tags/names, partner_tags/names) → cadena
CHAIN_RULES: list[dict] = [
    {
        "id": "web-sqli-to-db",
        "name": "SQLi web → acceso a base de datos",
        "triggers": {"sqli", "sql", "injection"},
        "partners": {"mysql", "database", "mssql", "postgres", "default-login", "db"},
        "chain": [
            "Explotar inyección SQL en endpoint web expuesto",
            "Bypass de autenticación o extracción de credenciales vía UNION/error-based",
            "Conectar a servicio de base de datos con credenciales obtenidas o por defecto",
            "Exfiltración de datos sensibles (PII, hashes, tokens)",
        ],
        "impact": "Compromiso de confidencialidad e integridad de datos corporativos",
    },
    {
        "id": "path-traversal-to-rce",
        "name": "Path traversal → lectura de config → escalada",
        "triggers": {"traversal", "lfi", "path", "file-read"},
        "partners": {"rce", "apache", "cgi", "config", "auth", "confluence"},
        "chain": [
            "Explotar path traversal para leer archivos del sistema (/etc/passwd, .env, configs)",
            "Extraer credenciales, API keys o rutas internas del archivo filtrado",
            "Reutilizar credenciales en panel admin o servicio colateral expuesto",
            "Escalada a ejecución remota o control del activo",
        ],
        "impact": "Compromiso total del servidor y posible movimiento lateral",
    },
    {
        "id": "auth-bypass-to-admin",
        "name": "Bypass de autenticación → panel administrativo",
        "triggers": {"auth-bypass", "auth", "login", "confluence", "admin"},
        "partners": {"default-login", "misconfig", "panel", "setup"},
        "chain": [
            "Explotar bypass de autenticación en aplicación expuesta",
            "Crear o secuestrar cuenta administrativa",
            "Acceder a funcionalidades críticas (despliegue, plugins, datos)",
        ],
        "impact": "Control administrativo de la aplicación y datos asociados",
    },
]


def _finding_tokens(finding: VulnFinding) -> set[str]:
    tokens: set[str] = set()
    tokens.update(tag.lower() for tag in finding.tags)
    for part in finding.name.lower().replace("-", " ").split():
        if len(part) > 2:
            tokens.add(part)
    for part in finding.template_id.lower().replace("-", " ").split():
        if len(part) > 2:
            tokens.add(part)
    if "sql" in finding.name.lower() or "sqli" in finding.template_id.lower():
        tokens.add("sqli")
    if "traversal" in finding.name.lower() or "traversal" in finding.template_id.lower():
        tokens.add("traversal")
    return tokens


def _matches(tokens: set[str], keywords: set[str]) -> bool:
    return bool(tokens & keywords) or any(kw in " ".join(tokens) for kw in keywords)


def _max_severity(findings: list[VulnFinding]) -> float:
    if not findings:
        return 0.0
    return max(SEVERITY_WEIGHT.get(f.severity, 3.0) for f in findings)


def _build_vector(
    rule: dict,
    trigger: VulnFinding,
    partner: VulnFinding,
    rank: int,
) -> AttackVector:
    findings = [trigger, partner]
    base_score = _max_severity(findings)
    chain_bonus = 1.5 * (len(findings) - 1)
    score = min(10.0, base_score + chain_bonus)

    return AttackVector(
        rank=rank,
        vector_id=f"{rule['id']}:{trigger.template_id}+{partner.template_id}",
        name=rule["name"],
        severity_score=round(score, 2),
        finding_ids=[trigger.template_id, partner.template_id],
        chain=list(rule["chain"]),
        justification=(
            f"Correlación automática: '{trigger.name}' ({trigger.severity.value}) en "
            f"{trigger.matched_at} habilita la cadena hacia '{partner.name}' "
            f"({partner.severity.value}) en {partner.matched_at}. "
            f"Ambos comparten host/IP ({trigger.ip or trigger.host})."
        ),
        estimated_impact=rule["impact"],
    )


def _standalone_vector(finding: VulnFinding, rank: int) -> AttackVector:
    score = SEVERITY_WEIGHT.get(finding.severity, 3.0)
    return AttackVector(
        rank=rank,
        vector_id=f"standalone:{finding.template_id}",
        name=f"Explotación directa: {finding.name}",
        severity_score=round(score, 2),
        finding_ids=[finding.template_id],
        chain=[
            f"Identificar superficie expuesta: {finding.matched_at}",
            f"Validar explotabilidad de {finding.name}",
            "Evaluar impacto en confidencialidad/integridad/disponibilidad",
        ],
        justification=(
            f"Hallazgo {finding.severity.value} detectado por plantilla '{finding.template_id}'. "
            f"{finding.description or 'Sin descripción adicional.'}"
        ),
        estimated_impact=f"Impacto proporcional a severidad {finding.severity.value}",
    )


def correlate_findings(findings: list[VulnFinding]) -> list[AttackVector]:
    """Correlaciona hallazgos HU-003/HU-006 en vectores encadenados ordenados por impacto."""
    if not findings:
        return []

    vectors: list[AttackVector] = []
    used_pairs: set[tuple[str, str]] = set()
    used_ids: set[str] = set()

    indexed = list(findings)
    token_map = {f.template_id: _finding_tokens(f) for f in indexed}

    for rule in CHAIN_RULES:
        triggers_kw = rule["triggers"]
        partners_kw = rule["partners"]

        for i, trigger in enumerate(indexed):
            if not _matches(token_map[trigger.template_id], triggers_kw):
                continue
            for partner in indexed:
                if partner.template_id == trigger.template_id:
                    continue
                pair_key = tuple(sorted([trigger.template_id, partner.template_id]))
                if pair_key in used_pairs:
                    continue
                if not _matches(token_map[partner.template_id], partners_kw):
                    continue
                if trigger.ip and partner.ip and trigger.ip != partner.ip:
                    continue

                used_pairs.add(pair_key)
                used_ids.add(trigger.template_id)
                used_ids.add(partner.template_id)
                vectors.append(_build_vector(rule, trigger, partner, rank=1))

    for finding in indexed:
        if finding.template_id not in used_ids:
            vectors.append(_standalone_vector(finding, rank=1))

    vectors.sort(key=lambda v: v.severity_score, reverse=True)
    for idx, vector in enumerate(vectors, start=1):
        vectors[idx - 1] = vector.model_copy(update={"rank": idx})

    return vectors
