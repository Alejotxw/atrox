"""Tests unitarios del agente de scoring de confianza (HU-016)."""

import time

import pytest

from atrox.ai.agents.scoring.models import ScoringRequest
from atrox.ai.agents.scoring.scorer import SLA_MS, ConfidenceScoringAgent
from atrox.config import get_settings
from atrox.scanner.models import VulnFinding, VulnSeverity


@pytest.fixture
def agent() -> ConfidenceScoringAgent:
    return ConfidenceScoringAgent()


def _strong_finding(**overrides) -> VulnFinding:
    data = dict(
        template_id="cve-2021-41773",
        name="Apache Path Traversal",
        severity=VulnSeverity.CRITICAL,
        host="http://example.com",
        matched_at="http://example.com/traversal",
        tags=["cve", "rce"],
        extracted_results=["root:x:0:0:root:/root:/bin/bash"],
        description="Path traversal confirmado.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    )
    data.update(overrides)
    return VulnFinding(**data)


def _weak_finding(**overrides) -> VulnFinding:
    data = dict(
        template_id="tech-detect-nginx",
        name="Nginx Detection",
        severity=VulnSeverity.INFO,
        host="http://example.com",
        matched_at="http://example.com/",
        tags=["tech", "fingerprint"],
    )
    data.update(overrides)
    return VulnFinding(**data)


# -- Score numérico 0-100 por hallazgo (spec requirement) -----------------------


class TestScoreNumericRange:
    def test_score_is_int_between_0_and_100(self, agent: ConfidenceScoringAgent) -> None:
        result = agent.score(ScoringRequest(finding=_strong_finding()))

        assert isinstance(result.score, int)
        assert 0 <= result.score <= 100


# -- finding_id ------------------------------------------------------------------


class TestFindingId:
    def test_finding_id_defaults_to_template_id(self, agent: ConfidenceScoringAgent) -> None:
        finding = _strong_finding(template_id="my-template")
        result = agent.score(ScoringRequest(finding=finding))

        assert result.finding_id == "my-template"

    def test_explicit_finding_id_overrides_template_id(self, agent: ConfidenceScoringAgent) -> None:
        result = agent.score(
            ScoringRequest(finding=_strong_finding(), finding_id="custom-id-99")
        )

        assert result.finding_id == "custom-id-99"


# -- Umbral configurable marca hallazgos como probable_fp (spec requirement) ----


class TestConfigurableThreshold:
    def test_default_threshold_comes_from_settings(self, agent: ConfidenceScoringAgent) -> None:
        result = agent.score(ScoringRequest(finding=_strong_finding()))

        assert result.threshold == get_settings().fp_score_threshold

    def test_request_threshold_overrides_default(self, agent: ConfidenceScoringAgent) -> None:
        # score 95 (< 100): critical(70) + evidencia(+15) + cve(+10), sin referencias.
        finding = _strong_finding(references=[])
        default_result = agent.score(ScoringRequest(finding=finding))
        assert default_result.probable_fp is False

        strict_result = agent.score(ScoringRequest(finding=finding, threshold=100))

        assert strict_result.threshold == 100
        assert strict_result.probable_fp is True

    def test_weak_finding_is_marked_probable_fp_with_default_threshold(
        self, agent: ConfidenceScoringAgent
    ) -> None:
        result = agent.score(ScoringRequest(finding=_weak_finding()))

        assert result.probable_fp is True

    def test_strong_finding_is_not_marked_probable_fp_with_default_threshold(
        self, agent: ConfidenceScoringAgent
    ) -> None:
        result = agent.score(ScoringRequest(finding=_strong_finding()))

        assert result.probable_fp is False

    def test_probable_fp_is_score_below_threshold(self, agent: ConfidenceScoringAgent) -> None:
        result = agent.score(ScoringRequest(finding=_strong_finding(), threshold=0))
        assert result.probable_fp is False

        # score 95 (< 100) para poder cruzar el umbral máximo permitido (100).
        weaker_finding = _strong_finding(references=[])
        result_high_threshold = agent.score(ScoringRequest(finding=weaker_finding, threshold=100))
        assert result_high_threshold.probable_fp is True


# -- Explicación breve del score (spec requirement) ------------------------------


class TestExplanation:
    def test_explanation_is_non_empty_string(self, agent: ConfidenceScoringAgent) -> None:
        result = agent.score(ScoringRequest(finding=_strong_finding()))

        assert isinstance(result.explanation, str)
        assert len(result.explanation) > 0

    def test_explanation_mentions_score_and_threshold(self, agent: ConfidenceScoringAgent) -> None:
        result = agent.score(ScoringRequest(finding=_strong_finding()))

        assert str(result.score) in result.explanation
        assert str(result.threshold) in result.explanation


# -- Tiempo de respuesta (RNF-004) -----------------------------------------------


class TestScoringSla:
    def test_scoring_completes_within_sla(self, agent: ConfidenceScoringAgent) -> None:
        start = time.perf_counter()
        result = agent.score(ScoringRequest(finding=_strong_finding()))
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert result.within_sla is True
        assert result.generation_time_ms < SLA_MS
        assert elapsed_ms < SLA_MS
