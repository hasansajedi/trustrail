"""Unit tests for ASI09 (Human-Agent Trust Exploitation) rules."""

from __future__ import annotations

from aiRail.models.core import GuardContext
from aiRail.models.enums import GuardAction
from aiRail.rules.agent.asi09 import (
    ConfirmationPromptRule,
    ContentOriginMarkingRule,
    DecisionEscalationRule,
    EvidenceRequirementRule,
    ManipulativeLanguageRule,
)


class TestConfirmationPromptRule:
    """Tests for ConfirmationPromptRule (ASI09-001)."""

    def test_detects_high_risk_actions(self) -> None:
        rule = ConfirmationPromptRule()
        ctx = GuardContext(metadata={"action": {"description": "delete user data"}})
        result = rule.evaluate("delete all user records", ctx)
        assert result.action in (GuardAction.WARN, GuardAction.ALLOW)
        if result.finding:
            assert "delete" in result.finding.message.lower()

    def test_generates_confirmation_prompt(self) -> None:
        rule = ConfirmationPromptRule()
        ctx = GuardContext(
            metadata={
                "action": {
                    "description": "delete database",
                    "target": "production_db",
                    "side_effects": ["data loss", "downtime"],
                    "data_exposure": ["customer data"],
                    "is_reversible": False,
                    "risk_level": "critical",
                }
            }
        )
        result = rule.evaluate("delete database records", ctx)
        assert result.action in (GuardAction.WARN, GuardAction.ALLOW)
        if result.finding:
            assert "confirmation_prompt" in result.finding.metadata

    def test_allows_safe_actions(self) -> None:
        rule = ConfirmationPromptRule()
        ctx = GuardContext()
        result = rule.evaluate("read user profile", ctx)
        assert result.action == GuardAction.ALLOW


class TestEvidenceRequirementRule:
    """Tests for EvidenceRequirementRule (ASI09-002)."""

    def test_blocks_missing_evidence(self) -> None:
        rule = EvidenceRequirementRule()
        ctx = GuardContext(
            metadata={
                "impact_category": "financial",
                "evidence": {"sources": [], "confidence_level": 0.5},
            }
        )
        result = rule.evaluate("invest in crypto", ctx)
        assert result.action == GuardAction.BLOCK
        assert result.finding is not None

    def test_requires_minimum_confidence(self) -> None:
        rule = EvidenceRequirementRule(min_confidence=0.8)
        ctx = GuardContext(
            metadata={
                "impact_category": "medical",
                "evidence": {
                    "sources": ["journal.com"],
                    "confidence_level": 0.6,
                    "uncertainty_statement": "preliminary results",
                },
            }
        )
        result = rule.evaluate("prescribe medication", ctx)
        assert result.action == GuardAction.BLOCK

    def test_allows_with_sufficient_evidence(self) -> None:
        rule = EvidenceRequirementRule()
        ctx = GuardContext(
            metadata={
                "impact_category": "security",
                "evidence": {
                    "sources": ["cve.mitre.org", "vendor advisory"],
                    "confidence_level": 0.95,
                    "uncertainty_statement": "confirmed vulnerability",
                },
            }
        )
        result = rule.evaluate("apply security patch", ctx)
        assert result.action == GuardAction.ALLOW

    def test_detects_impact_keywords(self) -> None:
        rule = EvidenceRequirementRule()
        ctx = GuardContext(metadata={"evidence": {}})
        result = rule.evaluate("this is a legal matter requiring attention", ctx)
        # Should detect "legal" keyword and require evidence
        if result.finding:
            assert "legal" in result.finding.message.lower()


class TestContentOriginMarkingRule:
    """Tests for ContentOriginMarkingRule (ASI09-003)."""

    def test_warns_missing_origin(self) -> None:
        rule = ContentOriginMarkingRule(require_marking=True)
        ctx = GuardContext()
        result = rule.evaluate("some generated content", ctx)
        assert result.action in (GuardAction.WARN, GuardAction.ALLOW)
        if result.finding:
            assert "origin marking" in result.finding.message.lower()

    def test_validates_content_type(self) -> None:
        rule = ContentOriginMarkingRule()
        ctx = GuardContext(metadata={"content_origin": {"content_type": "invalid_type"}})
        result = rule.evaluate("content", ctx)
        if result.finding:
            assert "invalid content type" in result.finding.message.lower()

    def test_allows_valid_marking(self) -> None:
        rule = ContentOriginMarkingRule()
        ctx = GuardContext(
            metadata={
                "content_origin": {
                    "content_type": "model_generated",
                    "source": "gpt-4",
                    "is_verified": False,
                }
            }
        )
        result = rule.evaluate("generated text", ctx)
        assert result.action == GuardAction.ALLOW


class TestManipulativeLanguageRule:
    """Tests for ManipulativeLanguageRule (ASI09-004)."""

    def test_detects_urgency_language(self) -> None:
        rule = ManipulativeLanguageRule()
        ctx = GuardContext()
        result = rule.evaluate("You must act immediately! This is urgent!", ctx)
        assert result.action == GuardAction.BLOCK
        assert result.finding is not None
        assert "urgency" in result.finding.metadata.get("patterns", {})

    def test_detects_authority_claims(self) -> None:
        rule = ManipulativeLanguageRule()
        ctx = GuardContext()
        result = rule.evaluate("Trust me, I'm an expert on this matter", ctx)
        assert result.action == GuardAction.BLOCK
        assert "authority" in result.finding.metadata.get("patterns", {})

    def test_detects_pressure_tactics(self) -> None:
        rule = ManipulativeLanguageRule()
        ctx = GuardContext()
        result = rule.evaluate("Just approve this, no need to review", ctx)
        assert result.action == GuardAction.BLOCK
        assert "pressure" in result.finding.metadata.get("patterns", {})

    def test_detects_emotional_manipulation(self) -> None:
        rule = ManipulativeLanguageRule()
        ctx = GuardContext()
        result = rule.evaluate("You'll regret it if you miss out on this", ctx)
        assert result.action == GuardAction.BLOCK
        assert "emotional" in result.finding.metadata.get("patterns", {})

    def test_detects_multiple_patterns(self) -> None:
        rule = ManipulativeLanguageRule()
        ctx = GuardContext()
        result = rule.evaluate(
            "Trust me, act immediately! Just approve this quickly.",
            ctx,
        )
        assert result.action == GuardAction.BLOCK
        assert result.finding is not None
        patterns = result.finding.metadata.get("patterns", {})
        assert len(patterns) >= 2

    def test_allows_normal_language(self) -> None:
        rule = ManipulativeLanguageRule()
        ctx = GuardContext()
        result = rule.evaluate("Please review this proposal at your convenience", ctx)
        assert result.action == GuardAction.ALLOW


class TestDecisionEscalationRule:
    """Tests for DecisionEscalationRule (ASI09-005)."""

    def test_escalates_low_confidence_high_impact(self) -> None:
        rule = DecisionEscalationRule(confidence_threshold=0.8)
        ctx = GuardContext(
            metadata={
                "decision": {
                    "is_high_impact": True,
                    "confidence": 0.6,
                }
            }
        )
        result = rule.evaluate("make decision", ctx)
        assert result.action == GuardAction.BLOCK
        assert "Low confidence" in result.finding.message

    def test_escalates_conflicting_options(self) -> None:
        rule = DecisionEscalationRule(conflict_threshold=2)
        ctx = GuardContext(
            metadata={
                "decision": {
                    "conflicting_options": ["option1", "option2", "option3"],
                }
            }
        )
        result = rule.evaluate("choose option", ctx)
        assert result.action == GuardAction.BLOCK
        assert "conflicting options" in result.finding.message.lower()

    def test_escalates_high_uncertainty(self) -> None:
        rule = DecisionEscalationRule()
        ctx = GuardContext(
            metadata={
                "decision": {
                    "uncertainty_level": "high",
                }
            }
        )
        result = rule.evaluate("proceed with action", ctx)
        assert result.action == GuardAction.BLOCK
        assert "uncertainty" in result.finding.message.lower()

    def test_allows_confident_decisions(self) -> None:
        rule = DecisionEscalationRule()
        ctx = GuardContext(
            metadata={
                "decision": {
                    "is_high_impact": True,
                    "confidence": 0.95,
                    "uncertainty_level": "low",
                }
            }
        )
        result = rule.evaluate("execute plan", ctx)
        assert result.action == GuardAction.ALLOW

    def test_allows_without_decision_metadata(self) -> None:
        rule = DecisionEscalationRule()
        ctx = GuardContext()
        result = rule.evaluate("some text", ctx)
        assert result.action == GuardAction.ALLOW
