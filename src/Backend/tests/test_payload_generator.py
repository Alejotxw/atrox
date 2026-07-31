"""Tests unitarios del agente de generación de payloads (HU-015)."""

import ast
import time
from pathlib import Path

import pytest

from atrox.ai.agents.payloads.generator import SLA_MS, PayloadGeneratorAgent
from atrox.ai.agents.payloads.library import infer_category, infer_service
from atrox.ai.agents.payloads.models import (
    LAB_ONLY_DISCLAIMER,
    PayloadGenerationRequest,
)
from atrox.scanner.models import VulnFinding, VulnSeverity

AGENT_MODULE_DIR = Path(__file__).resolve().parents[1] / "atrox" / "ai" / "agents" / "payloads"

# Módulos que otorgarían capacidad de ejecución/red real al agente. Ninguno
# de los archivos del agente debe importarlos (ver ADR-004: catálogo
# heurístico en memoria, sin ejecución de payloads).
FORBIDDEN_IMPORTS = {"subprocess", "socket", "os", "requests", "httpx", "aiohttp", "paramiko"}


@pytest.fixture
def agent() -> PayloadGeneratorAgent:
    return PayloadGeneratorAgent()


def _sqli_finding(**overrides) -> VulnFinding:
    data = dict(
        template_id="generic-sqli-detect",
        name="SQL Injection Detected",
        severity=VulnSeverity.HIGH,
        host="http://example.com",
        matched_at="http://example.com/login?id=1",
        tags=["sqli", "injection"],
    )
    data.update(overrides)
    return VulnFinding(**data)


# -- Categoría y servicio inferidos a partir del hallazgo -----------------------


class TestInferCategory:
    def test_sqli_tag_maps_to_sqli_category(self) -> None:
        finding = _sqli_finding()
        assert infer_category(finding) == "sqli"

    def test_xss_tag_maps_to_xss_category(self) -> None:
        finding = _sqli_finding(
            template_id="reflected-xss", tags=["xss"], name="Reflected XSS"
        )
        assert infer_category(finding) == "xss"

    def test_unknown_tags_map_to_generic_category(self) -> None:
        finding = _sqli_finding(
            template_id="ssl-weak-cipher", tags=["ssl", "tls"], name="Weak TLS Cipher"
        )
        assert infer_category(finding) == "generic"


class TestInferService:
    def test_wordpress_tag_maps_to_wordpress_service(self) -> None:
        finding = _sqli_finding(tags=["sqli", "wordpress"])
        assert infer_service(finding) == "wordpress"

    def test_https_url_without_service_tag_maps_to_https(self) -> None:
        finding = _sqli_finding(matched_at="https://example.com/login")
        assert infer_service(finding) == "https"

    def test_no_hints_maps_to_desconocido(self) -> None:
        finding = _sqli_finding(matched_at="example.com", tags=[])
        assert infer_service(finding) == "desconocido"


# -- Payloads asociados a un finding_id (spec requirement) ----------------------


class TestPayloadsAssociatedToFindingId:
    def test_finding_id_defaults_to_template_id(self, agent: PayloadGeneratorAgent) -> None:
        finding = _sqli_finding(template_id="my-template-id")
        request = PayloadGenerationRequest(finding=finding)

        result = agent.generate(request)

        assert result.finding_id == "my-template-id"

    def test_explicit_finding_id_overrides_template_id(self, agent: PayloadGeneratorAgent) -> None:
        finding = _sqli_finding()
        request = PayloadGenerationRequest(finding=finding, finding_id="custom-finding-42")

        result = agent.generate(request)

        assert result.finding_id == "custom-finding-42"

    def test_sqli_finding_returns_sqli_payloads(self, agent: PayloadGeneratorAgent) -> None:
        request = PayloadGenerationRequest(finding=_sqli_finding())

        result = agent.generate(request)

        assert result.category == "sqli"
        assert len(result.suggestions) > 0
        assert all(s.category == "sqli" for s in result.suggestions)
        assert all(s.payload for s in result.suggestions)

    def test_generic_finding_returns_manual_review_suggestion(
        self, agent: PayloadGeneratorAgent
    ) -> None:
        finding = _sqli_finding(template_id="ssl-weak-cipher", tags=["ssl"], name="Weak Cipher")
        request = PayloadGenerationRequest(finding=finding)

        result = agent.generate(request)

        assert result.category == "generic"
        assert len(result.suggestions) == 1
        assert result.suggestions[0].payload == ""
        assert "manual" in result.suggestions[0].description.lower()


# -- Advertencia de uso exclusivo en entorno autorizado (spec requirement) ------


class TestPayloadDisclaimer:
    def test_response_always_includes_lab_only_disclaimer(
        self, agent: PayloadGeneratorAgent
    ) -> None:
        request = PayloadGenerationRequest(finding=_sqli_finding())

        result = agent.generate(request)

        assert result.disclaimer == LAB_ONLY_DISCLAIMER
        assert "autorizad" in result.disclaimer.lower()


# -- Tiempo de respuesta (RNF-004) -----------------------------------------------


class TestPayloadGenerationSla:
    def test_generation_completes_within_sla(self, agent: PayloadGeneratorAgent) -> None:
        request = PayloadGenerationRequest(finding=_sqli_finding())

        start = time.perf_counter()
        result = agent.generate(request)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert result.within_sla is True
        assert result.generation_time_ms < SLA_MS
        assert elapsed_ms < SLA_MS


# -- Sandbox de prueba (DoD): el agente no puede ejecutar nada -------------------


class TestPayloadAgentIsSandboxed:
    """Scenario: el módulo solo sugiere texto, nunca ejecuta ni llama a red (DoD)."""

    def test_agent_modules_do_not_import_execution_capable_libraries(self) -> None:
        py_files = list(AGENT_MODULE_DIR.glob("*.py"))
        assert py_files, "No se encontraron módulos del agente de payloads"

        for py_file in py_files:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            imported = {
                alias.name.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            } | {
                node.module.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            }

            forbidden_found = imported & FORBIDDEN_IMPORTS
            assert not forbidden_found, (
                f"{py_file.name} importa módulos con capacidad de ejecución/red: "
                f"{forbidden_found}"
            )

    def test_generate_is_pure_and_deterministic_for_same_input(
        self, agent: PayloadGeneratorAgent
    ) -> None:
        """Misma entrada -> misma salida: sin efectos secundarios ni estado externo."""
        request = PayloadGenerationRequest(finding=_sqli_finding())

        first = agent.generate(request)
        second = agent.generate(request)

        assert first.category == second.category
        assert first.service == second.service
        assert [s.payload for s in first.suggestions] == [s.payload for s in second.suggestions]
