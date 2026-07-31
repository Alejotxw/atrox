"""Dataset de prueba etiquetado TP/FP para evaluar el agente de scoring (HU-016).

11 hallazgos son verdaderos positivos (`is_true_positive=True`, vulnerabilidad
real confirmada) y 11 son falsos positivos (`is_true_positive=False`, ruido).
Cada grupo incluye un caso "difícil" a propósito (ver `TRICKY_*`) para que la
métrica de precisión medida en `test_scoring_precision.py` no sea un 100%
artificial: un TP de severidad baja sin evidencia extraída (que la heurística
subestima) y un FP con tag `cve` heredado de un template mal calibrado (que
la heurística sobrestima). Documentado en
`docs/ai/HU-016-scoring-evaluation.md`.
"""

from dataclasses import dataclass

from atrox.scanner.models import VulnFinding, VulnSeverity


@dataclass(frozen=True)
class LabeledFinding:
    finding: VulnFinding
    is_true_positive: bool
    note: str = ""


def _finding(**kwargs) -> VulnFinding:
    kwargs.setdefault("description", "")
    kwargs.setdefault("references", [])
    kwargs.setdefault("extracted_results", [])
    return VulnFinding(**kwargs)


TRUE_POSITIVES: list[LabeledFinding] = [
    LabeledFinding(
        _finding(
            template_id="cve-2021-41773",
            name="Apache HTTP Server Path Traversal",
            severity=VulnSeverity.CRITICAL,
            host="http://192.168.1.10",
            matched_at="http://192.168.1.10/cgi-bin/.%2e/.%2e/etc/passwd",
            tags=["cve", "apache", "rce"],
            description="Path traversal confirmado, lectura de /etc/passwd.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
            extracted_results=["root:x:0:0:root:/root:/bin/bash"],
        ),
        is_true_positive=True,
    ),
    LabeledFinding(
        _finding(
            template_id="cve-2023-22515",
            name="Confluence Auth Bypass",
            severity=VulnSeverity.HIGH,
            host="http://192.168.1.10:8090",
            matched_at="http://192.168.1.10:8090/setup/setupadministrator.action",
            tags=["cve", "confluence"],
            description="Bypass de autenticación confirmado, cuenta admin creada.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-22515"],
            extracted_results=["admin session token issued"],
        ),
        is_true_positive=True,
    ),
    LabeledFinding(
        _finding(
            template_id="cve-2017-5638",
            name="Apache Struts2 RCE",
            severity=VulnSeverity.CRITICAL,
            host="http://10.0.0.5",
            matched_at="http://10.0.0.5/struts2-showcase/index.action",
            tags=["cve", "rce", "struts"],
            description="RCE confirmado vía Content-Type OGNL injection.",
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
                "https://struts.apache.org/security/S2-045.html",
            ],
            extracted_results=["uid=0(root) gid=0(root) groups=0(root)"],
        ),
        is_true_positive=True,
    ),
    LabeledFinding(
        _finding(
            template_id="cve-2019-0708",
            name="BlueKeep RDP RCE",
            severity=VulnSeverity.CRITICAL,
            host="10.0.0.7",
            matched_at="10.0.0.7:3389",
            tags=["cve", "rce", "rdp"],
            description="Servicio RDP vulnerable a BlueKeep, crash confirmado.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
            extracted_results=["target crashed after PoC packet"],
        ),
        is_true_positive=True,
    ),
    LabeledFinding(
        _finding(
            template_id="cve-2014-6271",
            name="Shellshock",
            severity=VulnSeverity.HIGH,
            host="http://10.0.0.9/cgi-bin/test.cgi",
            matched_at="http://10.0.0.9/cgi-bin/test.cgi",
            tags=["cve", "rce", "bash"],
            description="Ejecución remota de comandos vía variable de entorno maliciosa.",
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
                "https://access.redhat.com/security/cve/cve-2014-6271",
            ],
            extracted_results=["uid=33(www-data) gid=33(www-data)"],
        ),
        is_true_positive=True,
    ),
    LabeledFinding(
        _finding(
            template_id="sqli-error-based-detect",
            name="SQL Injection (error-based)",
            severity=VulnSeverity.HIGH,
            host="http://example.com",
            matched_at="http://example.com/product?id=1'",
            tags=["sqli", "injection"],
            description="Inyección SQL confirmada vía mensaje de error de sintaxis.",
            extracted_results=["SQL syntax error near ''1''' at line 1"],
        ),
        is_true_positive=True,
    ),
    LabeledFinding(
        _finding(
            template_id="exposed-git-config",
            name="Exposed .git/config",
            severity=VulnSeverity.MEDIUM,
            host="http://example.com",
            matched_at="http://example.com/.git/config",
            tags=["exposure", "git"],
            description="Archivo de configuración de repositorio Git expuesto públicamente.",
            extracted_results=["[core]\n\trepositoryformatversion = 0"],
        ),
        is_true_positive=True,
    ),
    LabeledFinding(
        _finding(
            template_id="cve-2022-22965",
            name="Spring4Shell RCE",
            severity=VulnSeverity.CRITICAL,
            host="http://10.0.0.20",
            matched_at="http://10.0.0.20/helloworld",
            tags=["cve", "rce", "spring"],
            description="RCE confirmado por class loader manipulation.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
            extracted_results=["shell.jsp escrito en webroot"],
        ),
        is_true_positive=True,
    ),
    LabeledFinding(
        _finding(
            template_id="jenkins-unauth-script-console",
            name="Jenkins Unauthenticated Script Console",
            severity=VulnSeverity.HIGH,
            host="http://10.0.0.30:8080",
            matched_at="http://10.0.0.30:8080/script",
            tags=["jenkins", "rce"],
            description="Consola de script accesible sin autenticación, comando ejecutado.",
            extracted_results=["Jenkins 2.303 - script console executed 'whoami'"],
        ),
        is_true_positive=True,
    ),
    LabeledFinding(
        _finding(
            template_id="wp-admin-default-creds",
            name="WordPress Default Admin Credentials",
            severity=VulnSeverity.HIGH,
            host="http://blog.example.com",
            matched_at="http://blog.example.com/wp-login.php",
            tags=["wordpress", "default-login"],
            description="Login exitoso con credenciales admin:admin.",
            extracted_results=["login successful with admin:admin"],
        ),
        is_true_positive=True,
    ),
    LabeledFinding(
        _finding(
            template_id="auth-bypass-logic-flaw",
            name="Business Logic Auth Bypass (confirmado manualmente)",
            severity=VulnSeverity.LOW,
            host="http://example.com",
            matched_at="http://example.com/api/v1/account?id=other_user",
            tags=["detect", "auth"],
            description="",
            extracted_results=[],
        ),
        is_true_positive=True,
        note=(
            "TRICKY: vulnerabilidad real confirmada manualmente por el analista "
            "(IDOR), pero el template Nuclei solo la reporta como 'detect' de baja "
            "severidad sin evidencia extraída — la heurística la subestima (falso "
            "negativo esperado)."
        ),
    ),
]


FALSE_POSITIVES: list[LabeledFinding] = [
    LabeledFinding(
        _finding(
            template_id="tech-detect-nginx",
            name="Nginx Version Detection",
            severity=VulnSeverity.INFO,
            host="http://example.com",
            matched_at="http://example.com/",
            tags=["tech", "fingerprint"],
        ),
        is_true_positive=False,
    ),
    LabeledFinding(
        _finding(
            template_id="ssl-cert-info",
            name="SSL Certificate Info",
            severity=VulnSeverity.INFO,
            host="https://example.com",
            matched_at="https://example.com:443",
            tags=["ssl", "tls"],
        ),
        is_true_positive=False,
    ),
    LabeledFinding(
        _finding(
            template_id="panel-detect-admin",
            name="Admin Panel Detected",
            severity=VulnSeverity.LOW,
            host="http://example.com",
            matched_at="http://example.com/admin",
            tags=["panel", "detect"],
        ),
        is_true_positive=False,
    ),
    LabeledFinding(
        _finding(
            template_id="wappalyzer-tech-detect",
            name="Technology Stack Detection",
            severity=VulnSeverity.INFO,
            host="http://example.com",
            matched_at="http://example.com/",
            tags=["tech"],
        ),
        is_true_positive=False,
    ),
    LabeledFinding(
        _finding(
            template_id="http-title-detect",
            name="HTTP Title Detection",
            severity=VulnSeverity.INFO,
            host="http://example.com",
            matched_at="http://example.com/",
            tags=["detect"],
        ),
        is_true_positive=False,
    ),
    LabeledFinding(
        _finding(
            template_id="tls-version-detect",
            name="TLS Version Detection",
            severity=VulnSeverity.INFO,
            host="https://example.com",
            matched_at="https://example.com:443",
            tags=["tls", "ssl"],
        ),
        is_true_positive=False,
    ),
    LabeledFinding(
        _finding(
            template_id="favicon-detect",
            name="Favicon Hash Detection",
            severity=VulnSeverity.INFO,
            host="http://example.com",
            matched_at="http://example.com/favicon.ico",
            tags=["fingerprint"],
        ),
        is_true_positive=False,
    ),
    LabeledFinding(
        _finding(
            template_id="robots-txt-detect",
            name="robots.txt Detected",
            severity=VulnSeverity.LOW,
            host="http://example.com",
            matched_at="http://example.com/robots.txt",
            tags=["detect"],
        ),
        is_true_positive=False,
    ),
    LabeledFinding(
        _finding(
            template_id="server-header-disclosure",
            name="Server Header Disclosure",
            severity=VulnSeverity.LOW,
            host="http://example.com",
            matched_at="http://example.com/",
            tags=["tech", "detect"],
        ),
        is_true_positive=False,
    ),
    LabeledFinding(
        _finding(
            template_id="openssh-version-detect",
            name="OpenSSH Version Detection",
            severity=VulnSeverity.INFO,
            host="10.0.0.1",
            matched_at="10.0.0.1:22",
            tags=["ssh", "fingerprint"],
        ),
        is_true_positive=False,
    ),
    LabeledFinding(
        _finding(
            template_id="cve-generic-banner-match",
            name="CVE Banner Match (Generic)",
            severity=VulnSeverity.HIGH,
            host="http://example.com",
            matched_at="http://example.com/",
            tags=["cve", "tech"],
            description=(
                "Coincidencia automática por banner genérico de versión; alto "
                "historial de falsos positivos para este template."
            ),
            references=["https://nvd.nist.gov/vuln/detail/CVE-2020-99999"],
            extracted_results=["Server: nginx/1.18.0"],
        ),
        is_true_positive=False,
        note=(
            "TRICKY: falso positivo conocido — template mal calibrado que asigna "
            "tag 'cve' y severidad alta a partir de un simple banner grab. La "
            "heurística lo sobrestima (falso positivo del clasificador esperado)."
        ),
    ),
]


LABELED_DATASET: list[LabeledFinding] = TRUE_POSITIVES + FALSE_POSITIVES
