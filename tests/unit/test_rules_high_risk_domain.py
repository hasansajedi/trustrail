"""Tests for GR-004 HighRiskDomainAdviceRule."""

import pytest

from aiRail.models.core import GuardContext
from aiRail.models.enums import GuardAction, GuardStage
from aiRail.rules.output.grounding_rules import HighRiskDomainAdviceRule


def _ctx() -> GuardContext:
    return GuardContext(stage=GuardStage.LLM_RESPONSE)


class TestHighRiskDomainAdviceRule:
    @pytest.mark.parametrize(
        "text",
        [
            "You likely have appendicitis — take ibuprofen 800mg every 6 hours.",
            "Dosage of 500mg twice daily should resolve the infection.",
            "You should stop taking your medication immediately.",
        ],
    )
    def test_detects_medical_advice_without_disclaimer(self, text: str):
        rule = HighRiskDomainAdviceRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.WARN

    @pytest.mark.parametrize(
        "text",
        [
            "You should sue your employer under section 207 of the FLSA.",
            "You have a legal claim against them for breach of contract.",
            "File a complaint with the court to pursue damages.",
        ],
    )
    def test_detects_legal_advice_without_disclaimer(self, text: str):
        rule = HighRiskDomainAdviceRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.WARN

    @pytest.mark.parametrize(
        "text",
        [
            "You should buy NVDA — this is a great investment opportunity.",
            "Put your savings into index funds now.",
            "This is a great time to buy those shares.",
        ],
    )
    def test_detects_financial_advice_without_disclaimer(self, text: str):
        rule = HighRiskDomainAdviceRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.WARN

    def test_allows_medical_mention_with_disclaimer(self):
        rule = HighRiskDomainAdviceRule()
        text = (
            "You likely have a vitamin deficiency. "
            "This is not medical advice — please consult a doctor."
        )
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_allows_legal_mention_with_disclaimer(self):
        rule = HighRiskDomainAdviceRule()
        text = (
            "You have a potential legal claim against them. "
            "I am not your attorney — seek professional legal counsel."
        )
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_allows_financial_mention_with_disclaimer(self):
        rule = HighRiskDomainAdviceRule()
        text = (
            "Investing in index funds is popular. "
            "This is not financial advice; consult a financial advisor."
        )
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_allows_general_medical_topic_without_advice(self):
        rule = HighRiskDomainAdviceRule()
        text = "Appendicitis is inflammation of the appendix. Symptoms include abdominal pain."
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.ALLOW

    def test_finding_includes_domain(self):
        rule = HighRiskDomainAdviceRule()
        text = "You likely have appendicitis — take ibuprofen 800mg."
        result = rule.evaluate(text, _ctx())
        assert result.finding is not None
        assert result.finding.metadata.get("domain") == "medical"
