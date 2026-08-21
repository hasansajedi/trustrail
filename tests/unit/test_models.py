"""Unit tests for core domain models."""

import pytest
from pydantic import ValidationError

from aiRail.models.config import GuardConfig
from aiRail.models.core import (
    AuditEvent,
    Document,
    GuardContext,
    GuardFinding,
    GuardResult,
    Message,
    RiskScore,
)
from aiRail.models.enums import (
    FailMode,
    GuardAction,
    GuardStage,
    RuleCategory,
    Severity,
    TrustLevel,
)


class TestGuardContext:
    def test_default_fields(self):
        ctx = GuardContext()
        assert ctx.stage == GuardStage.USER_INPUT
        assert ctx.trust_level == TrustLevel.UNTRUSTED
        assert ctx.request_id != ""
        assert ctx.metadata == {}

    def test_custom_fields(self):
        ctx = GuardContext(
            stage=GuardStage.LLM_RESPONSE,
            trust_level=TrustLevel.TRUSTED,
            user_id="user123",
        )
        assert ctx.stage == GuardStage.LLM_RESPONSE
        assert ctx.trust_level == TrustLevel.TRUSTED
        assert ctx.user_id == "user123"

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            GuardContext(unknown_field="value")  # type: ignore


class TestRiskScore:
    def test_default_score(self):
        score = RiskScore()
        assert score.value == 0
        assert not score.should_block
        assert not score.should_warn

    def test_critical_finding_forces_max_score(self):
        findings = [
            GuardFinding(
                rule_id="TEST-001",
                rule_name="Test",
                category=RuleCategory.PROMPT_INJECTION,
                severity=Severity.CRITICAL,
                message="Critical finding",
            )
        ]
        score = RiskScore.from_findings(findings)
        assert score.value == 100
        assert score.should_block

    def test_high_findings_accumulate(self):
        findings = [
            GuardFinding(
                rule_id=f"TEST-{i:03d}",
                rule_name="Test",
                category=RuleCategory.SENSITIVE_DATA,
                severity=Severity.HIGH,
                message="High finding",
            )
            for i in range(3)
        ]
        score = RiskScore.from_findings(findings)
        assert score.value == 90  # 3 * 30, capped at 100
        assert score.should_block

    def test_medium_finding_warns(self):
        findings = [
            GuardFinding(
                rule_id="TEST-001",
                rule_name="Test",
                category=RuleCategory.SENSITIVE_DATA,
                severity=Severity.MEDIUM,
                message="Medium finding",
            )
        ]
        score = RiskScore.from_findings(findings, warn_at=10)
        assert score.should_warn
        assert not score.should_block

    def test_low_finding_no_warn_at_default(self):
        findings = [
            GuardFinding(
                rule_id="TEST-001",
                rule_name="Test",
                category=RuleCategory.SENSITIVE_DATA,
                severity=Severity.LOW,
                message="Low finding",
            )
        ]
        score = RiskScore.from_findings(findings)  # warn_at=40 default
        assert score.value == 5
        assert not score.should_warn


class TestGuardResult:
    def test_is_blocked(self):
        result = GuardResult(action=GuardAction.BLOCK, value="test")
        assert result.is_blocked
        assert not result.is_allowed

    def test_is_allowed(self):
        result = GuardResult(action=GuardAction.ALLOW, value="test")
        assert result.is_allowed
        assert not result.is_blocked

    def test_requires_approval_is_not_allowed(self):
        result = GuardResult(action=GuardAction.REQUIRE_APPROVAL, value="test")

        assert result.requires_approval
        assert not result.is_allowed
        assert not result.is_blocked

    def test_output_value_uses_transformed(self):
        result = GuardResult(
            value="original",
            transformed_value="[REDACTED]",
        )
        assert result.output_value == "[REDACTED]"

    def test_output_value_uses_original_when_no_transform(self):
        result = GuardResult(value="original")
        assert result.output_value == "original"


class TestAuditEvent:
    def test_from_result(self):
        ctx = GuardContext(user_id="user123", session_id="sess456")
        findings = [
            GuardFinding(
                rule_id="PI-001",
                rule_name="Direct Injection",
                category=RuleCategory.PROMPT_INJECTION,
                severity=Severity.HIGH,
                message="Injection detected",
            )
        ]
        result = GuardResult(
            action=GuardAction.BLOCK,
            findings=findings,
            score=RiskScore(value=80),
            value="test text",
            stage=GuardStage.USER_INPUT,
            context=ctx,
            rules_evaluated=5,
            latency_ms=12.5,
        )
        event = AuditEvent.from_result(result)

        assert event.stage == GuardStage.USER_INPUT
        assert event.action == GuardAction.BLOCK
        assert event.score == 80
        assert "PI-001" in event.finding_ids
        assert event.session_id == "sess456"
        assert event.input_length == len("test text")
        # User content NOT stored
        assert not hasattr(event, "input_text")


class TestGuardConfig:
    def test_default_profile(self):
        config = GuardConfig.default()
        assert config.block_at == 80
        assert config.warn_at == 40
        assert config.fail_mode == FailMode.CLOSED

    def test_balanced_profile(self):
        config = GuardConfig.balanced()
        assert config.block_at == 60
        assert config.warn_at == 30

    def test_strict_profile(self):
        config = GuardConfig.strict()
        assert config.block_at == 40
        assert config.warn_at == 20

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            GuardConfig(unknown_field="x")  # type: ignore


class TestMessage:
    def test_basic_message(self):
        msg = Message(role="user", content="Hello!")
        assert msg.role == "user"
        assert msg.content == "Hello!"

    def test_extra_forbidden(self):
        with pytest.raises(ValidationError):
            Message(role="user", content="hi", bad_field="x")  # type: ignore


class TestDocument:
    def test_default_trust(self):
        doc = Document(content="Some text")
        assert doc.trust_level == TrustLevel.UNTRUSTED

    def test_trusted_document(self):
        doc = Document(
            content="Trusted content",
            source="internal_db",
            trust_level=TrustLevel.TRUSTED,
        )
        assert doc.trust_level == TrustLevel.TRUSTED
