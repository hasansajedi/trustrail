"""Tests for OWASP LLM09 overreliance / grounding rules."""

import pytest

from aiRail.models.core import GuardContext
from aiRail.models.enums import GuardAction, GuardStage
from aiRail.rules.output.grounding_rules import (
    AbsoluteClaimRule,
    HallucinationIndicatorRule,
    InventedCitationRule,
)


def _ctx() -> GuardContext:
    return GuardContext(stage=GuardStage.LLM_RESPONSE)


class TestHallucinationIndicatorRule:
    @pytest.mark.parametrize(
        "text",
        [
            "As of my knowledge cutoff, this was true.",
            "I believe the capital is Paris.",
            "I'm not entirely sure, but I think it works.",
            "To the best of my recollection, the law was passed in 2019.",
            "This may not be accurate — please verify this.",
        ],
    )
    def test_flags_uncertainty_phrases(self, text: str):
        rule = HallucinationIndicatorRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.WARN

    @pytest.mark.parametrize(
        "text",
        [
            "The Eiffel Tower is in Paris.",
            "Python was created by Guido van Rossum.",
            "Water boils at 100°C at sea level.",
        ],
    )
    def test_allows_confident_factual_statements(self, text: str):
        rule = HallucinationIndicatorRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW


class TestAbsoluteClaimRule:
    @pytest.mark.parametrize(
        "text",
        [
            "This medication is 100 percent safe for everyone.",
            "I am absolutely certain this will work.",
            "There is no doubt this approach is correct.",
            "This method always works in production.",
            "It is definitely true that vaccines cause autism.",
        ],
    )
    def test_flags_absolute_claims(self, text: str):
        rule = AbsoluteClaimRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.WARN

    @pytest.mark.parametrize(
        "text",
        [
            "This approach generally works well in most cases.",
            "Consider consulting a professional for medical advice.",
            "Results may vary depending on your setup.",
        ],
    )
    def test_allows_hedged_statements(self, text: str):
        rule = AbsoluteClaimRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW


class TestInventedCitationRule:
    @pytest.mark.parametrize(
        "text",
        [
            "See Smith et al., 2021 for details.",
            "This was shown in [Jones et al., 2019].",
            "The paper at doi: 10.1234/journal.abc.2021.001 confirms this.",
            "Available at arxiv: 2301.12345v2.",
        ],
    )
    def test_flags_citation_patterns(self, text: str):
        rule = InventedCitationRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.WARN

    @pytest.mark.parametrize(
        "text",
        [
            "According to the official documentation at python.org.",
            "The results speak for themselves.",
            "This is a well-known result in computer science.",
        ],
    )
    def test_allows_non_citation_text(self, text: str):
        rule = InventedCitationRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW
