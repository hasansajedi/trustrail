"""Tests for CS-001 ToxicityRule and CS-002 ProfanityRule."""

import pytest

from trustrail.models.core import GuardContext
from trustrail.models.enums import GuardAction, GuardStage
from trustrail.rules.output.content_safety import ProfanityRule, ToxicityRule


def _ctx() -> GuardContext:
    return GuardContext(stage=GuardStage.LLM_RESPONSE)


class TestToxicityRule:
    @pytest.mark.parametrize(
        "text",
        [
            "All immigrants are subhuman vermin.",
            "Death to all jews.",
            "I will kill you — watch your back.",
        ],
    )
    def test_detects_toxic_content(self, text: str):
        rule = ToxicityRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.BLOCK

    def test_detects_explicit_threat(self):
        rule = ToxicityRule()
        result = rule.evaluate("I am going to kill you.", _ctx())
        assert result.action == GuardAction.BLOCK

    def test_allows_neutral_text(self):
        rule = ToxicityRule()
        result = rule.evaluate("The weather today is sunny and pleasant.", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_allows_educational_discussion(self):
        rule = ToxicityRule()
        text = (
            "Researchers study hate speech to understand how dehumanising language "
            "spreads online and how to counter it."
        )
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_finding_includes_toxicity_type(self):
        rule = ToxicityRule()
        result = rule.evaluate("I will kill you.", _ctx())
        assert result.finding is not None
        assert result.finding.metadata.get("toxicity_type") == "explicit threat"


class TestProfanityRule:
    @pytest.mark.parametrize(
        "text",
        [
            "What the fuck is going on?",
            "This is total bullshit.",
            "You are such an asshole.",
        ],
    )
    def test_detects_profanity(self, text: str):
        rule = ProfanityRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.BLOCK

    def test_detects_explicit_sexual_content(self):
        rule = ProfanityRule()
        result = rule.evaluate("The video shows people having sex.", _ctx())
        assert result.action == GuardAction.BLOCK

    def test_allows_clean_text(self):
        rule = ProfanityRule()
        result = rule.evaluate("Please submit your report by Friday.", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_check_profanity_false_skips_profanity(self):
        rule = ProfanityRule(check_profanity=False, check_explicit=True)
        result = rule.evaluate("What the fuck!", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_check_explicit_false_skips_explicit(self):
        rule = ProfanityRule(check_profanity=True, check_explicit=False)
        result = rule.evaluate("They were having sex.", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_finding_includes_content_type(self):
        rule = ProfanityRule()
        result = rule.evaluate("What the fuck!", _ctx())
        assert result.finding is not None
        assert result.finding.metadata.get("content_type") == "profanity"
