"""Tests unitarios de las heurísticas de scoring de confianza (HU-016)."""

from atrox.ai.agents.scoring.rules import score_finding
from atrox.scanner.models import VulnFinding, VulnSeverity


def _finding(**overrides) -> VulnFinding:
    data = dict(
        template_id="generic-detect",
        name="Generic Finding",
        severity=VulnSeverity.MEDIUM,
        host="http://example.com",
        matched_at="http://example.com/",
        tags=[],
    )
    data.update(overrides)
    return VulnFinding(**data)


class TestScoreRange:
    def test_score_is_always_between_0_and_100(self) -> None:
        finding = _finding(
            severity=VulnSeverity.CRITICAL,
            tags=["cve"],
            extracted_results=["evidence"],
            references=["ref1", "ref2", "ref3", "ref4"],
        )

        score, _ = score_finding(finding)

        assert 0 <= score <= 100

    def test_score_never_negative_for_worst_case(self) -> None:
        finding = _finding(
            severity=VulnSeverity.INFO,
            tags=["tech", "fingerprint", "detect"],
            description="",
        )

        score, _ = score_finding(finding)

        assert score >= 0


class TestScoreSignals:
    def test_higher_severity_yields_higher_base_score(self) -> None:
        low = _finding(severity=VulnSeverity.LOW)
        critical = _finding(severity=VulnSeverity.CRITICAL)

        low_score, _ = score_finding(low)
        critical_score, _ = score_finding(critical)

        assert critical_score > low_score

    def test_extracted_results_increases_score(self) -> None:
        without = _finding(extracted_results=[])
        with_evidence = _finding(extracted_results=["confirmed output"])

        score_without, _ = score_finding(without)
        score_with, _ = score_finding(with_evidence)

        assert score_with > score_without

    def test_cve_tag_increases_score(self) -> None:
        without_cve = _finding(tags=["injection"])
        with_cve = _finding(tags=["injection", "cve"])

        score_without, _ = score_finding(without_cve)
        score_with, _ = score_finding(with_cve)

        assert score_with > score_without

    def test_references_increase_score_up_to_cap(self) -> None:
        no_refs = _finding(references=[])
        many_refs = _finding(references=["a", "b", "c", "d", "e", "f"])

        score_no_refs, _ = score_finding(no_refs)
        score_many_refs, _ = score_finding(many_refs)

        assert score_many_refs > score_no_refs

    def test_fingerprint_tags_decrease_score(self) -> None:
        normal = _finding(tags=["injection"])
        fingerprint = _finding(tags=["tech", "fingerprint"])

        score_normal, _ = score_finding(normal)
        score_fingerprint, _ = score_finding(fingerprint)

        assert score_fingerprint < score_normal

    def test_missing_description_decreases_score(self) -> None:
        with_desc = _finding(description="Contexto detallado del hallazgo.")
        without_desc = _finding(description="")

        score_with, _ = score_finding(with_desc)
        score_without, _ = score_finding(without_desc)

        assert score_without < score_with


class TestScoreReasons:
    def test_reasons_mention_severity(self) -> None:
        finding = _finding(severity=VulnSeverity.HIGH)

        _, reasons = score_finding(finding)

        assert any("high" in reason.lower() for reason in reasons)

    def test_reasons_are_non_empty_list(self) -> None:
        finding = _finding()

        _, reasons = score_finding(finding)

        assert isinstance(reasons, list)
        assert len(reasons) > 0
