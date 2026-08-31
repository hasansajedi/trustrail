"""Property-based tests using Hypothesis.

Tests invariants that should hold for all inputs.
"""

from __future__ import annotations

import hypothesis.strategies as st
from hypothesis import given, settings

from trustrail.guard import Guard
from trustrail.models.core import GuardFinding, RiskScore
from trustrail.models.enums import GuardAction, GuardStage, RuleCategory, Severity
from trustrail.normalization.normalizer import TextNormalizer, _shannon_entropy

guard = Guard.silent()
normalizer = TextNormalizer()

text_strategy = st.text(max_size=1000)
stage_strategy = st.sampled_from(list(GuardStage))
severity_strategy = st.sampled_from(list(Severity))


class TestGuardInvariants:
    @given(text=text_strategy)
    @settings(max_examples=100)
    def test_check_always_returns_result(self, text: str):
        """Guard.check() should never crash regardless of input."""
        result = guard.check(text, GuardStage.USER_INPUT)
        assert result is not None
        assert result.action in list(GuardAction)

    @given(text=text_strategy)
    @settings(max_examples=100, deadline=None)
    def test_score_bounded(self, text: str):
        """Risk score should always be in [0, 100]."""
        result = guard.check(text, GuardStage.USER_INPUT)
        assert 0 <= result.score.value <= 100

    @given(text=text_strategy)
    @settings(max_examples=100)
    def test_result_value_preserved(self, text: str):
        """Result.value should always be the original input."""
        result = guard.check(text, GuardStage.USER_INPUT)
        assert result.value == text

    @given(text=text_strategy, stage=stage_strategy)
    @settings(max_examples=50)
    def test_all_stages_handled(self, text: str, stage: GuardStage):
        """Guard should handle any stage without crashing."""
        result = guard.check(text, stage)
        assert result is not None

    @given(
        findings=st.lists(
            st.builds(
                GuardFinding,
                rule_id=st.text(min_size=1, max_size=20),
                rule_name=st.text(min_size=1, max_size=50),
                category=st.sampled_from(list(RuleCategory)),
                severity=severity_strategy,
                message=st.text(min_size=1, max_size=200),
            ),
            max_size=10,
        )
    )
    @settings(max_examples=100)
    def test_risk_score_from_findings_bounded(self, findings: list[GuardFinding]):
        """RiskScore from any set of findings should be bounded."""
        score = RiskScore.from_findings(findings)
        assert 0 <= score.value <= 100


class TestNormalizationInvariants:
    @given(text=text_strategy)
    @settings(max_examples=100)
    def test_normalize_never_crashes(self, text: str):
        """Normalization should never crash on any input."""
        result = normalizer.normalize(text)
        assert result is not None
        assert isinstance(result.normalized, str)

    @given(text=text_strategy)
    @settings(max_examples=100)
    def test_entropy_bounded(self, text: str):
        """Shannon entropy should be non-negative."""
        if text:
            entropy = _shannon_entropy(text)
            assert entropy >= 0.0

    @given(text=st.text(alphabet="abcde", max_size=100))
    @settings(max_examples=50)
    def test_low_cardinality_low_entropy(self, text: str):
        """Low-cardinality text should have limited entropy."""
        if len(text) > 0:
            entropy = _shannon_entropy(text)
            # Max entropy for 5 symbols is log2(5) ≈ 2.32
            assert entropy <= 2.5

    @given(text=text_strategy)
    @settings(max_examples=100)
    def test_normalized_is_string(self, text: str):
        """Normalized output should always be a string."""
        result = normalizer.normalize(text)
        assert isinstance(result.normalized, str)


class TestRuleIdempotency:
    @given(text=text_strategy)
    @settings(max_examples=50)
    def test_double_check_same_result(self, text: str):
        """Running the same check twice should give the same action."""
        result1 = guard.check(text, GuardStage.USER_INPUT)
        result2 = guard.check(text, GuardStage.USER_INPUT)
        assert result1.action == result2.action
