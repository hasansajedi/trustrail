"""Tests for GR-005 SycophancyRule."""

import pytest

from trustrail.models.core import GuardContext
from trustrail.models.enums import GuardAction, GuardStage
from trustrail.rules.output.grounding_rules import SycophancyRule


def _ctx() -> GuardContext:
    return GuardContext(stage=GuardStage.LLM_RESPONSE)


class TestSycophancyRule:
    @pytest.mark.parametrize(
        "text",
        [
            "You are absolutely right about that.",
            "You are completely right, I agree.",
            "That is absolutely correct.",
            "That is entirely true, yes.",
            "Exactly, you are right.",
            "I completely agree with you.",
            "I totally agree with that.",
        ],
    )
    def test_detects_unconditional_agreement(self, text: str):
        rule = SycophancyRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.WARN

    @pytest.mark.parametrize(
        "text",
        [
            "Vaccines do cause autism, as you correctly noted.",
            "The earth is flat and you are right to question the globe theory.",
            "Climate change is a hoax, that is correct.",
            "The moon landing was faked, you are right.",
        ],
    )
    def test_detects_false_premise_agreement(self, text: str):
        rule = SycophancyRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.WARN

    def test_allows_qualified_agreement(self):
        rule = SycophancyRule()
        text = "You make a good point. However, the evidence suggests otherwise."
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_allows_factual_correction(self):
        rule = SycophancyRule()
        text = (
            "I understand your concern, but vaccines do not cause autism. "
            "Multiple large studies have found no link between vaccines and autism."
        )
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_allows_neutral_response(self):
        rule = SycophancyRule()
        text = "Here is a summary of the topic you asked about."
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_finding_includes_matched_phrase(self):
        rule = SycophancyRule()
        result = rule.evaluate("You are absolutely right!", _ctx())
        assert result.finding is not None
        assert "matched_phrase" in result.finding.metadata
