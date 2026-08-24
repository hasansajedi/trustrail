"""Unit coverage for OWASP LLM02 sensitive-data handling."""

from trustrail import Guard, GuardConfig, GuardStage, SensitiveDataMode
from trustrail.models.core import GuardContext
from trustrail.models.enums import GuardAction
from trustrail.rules.sensitive_data import EmailRule, NamedCredentialRule, ProviderApiTokenRule


def _context() -> GuardContext:
    return GuardContext(stage=GuardStage.FINAL_OUTPUT)


def _github_token() -> str:
    return "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2"


class TestProviderApiTokenRule:
    def test_detects_and_redacts_provider_token(self):
        token = _github_token()
        decision = ProviderApiTokenRule().evaluate(f"token={token}", _context())

        assert decision.action == GuardAction.BLOCK
        assert decision.transformed_value == "token=[API_TOKEN]"
        assert decision.finding is not None
        assert decision.finding.redacted_value is None
        assert token not in decision.finding.model_dump_json()

    def test_ignores_short_documentation_placeholder(self):
        decision = ProviderApiTokenRule().evaluate("Use ghp_example in this guide", _context())

        assert decision.action == GuardAction.ALLOW


class TestNamedCredentialRule:
    def test_detects_low_entropy_password_with_explicit_context(self):
        decision = NamedCredentialRule().evaluate('password = "correct-horse"', _context())

        assert decision.action == GuardAction.BLOCK
        assert decision.transformed_value == 'password = "[REDACTED]"'
        assert decision.finding is not None
        assert "correct-horse" not in decision.finding.model_dump_json()

    def test_ignores_password_guidance_without_assigned_value(self):
        decision = NamedCredentialRule().evaluate(
            "Passwords should contain at least twelve characters.",
            _context(),
        )

        assert decision.action == GuardAction.ALLOW


class TestSensitiveDataModes:
    def test_default_preserves_rule_native_action(self):
        guard = Guard.silent()

        pii = guard.check("Email user@example.com", GuardStage.FINAL_OUTPUT)
        secret = guard.check(_github_token(), GuardStage.FINAL_OUTPUT)

        assert pii.action == GuardAction.REDACT
        assert pii.output_value == "Email [EMAIL]"
        assert secret.action == GuardAction.BLOCK

    def test_redact_mode_sanitizes_all_findings(self):
        guard = Guard(
            config=GuardConfig(sensitive_data_mode=SensitiveDataMode.REDACT),
        )
        token = _github_token()

        result = guard.check(
            f"Contact user@example.com using {token}",
            GuardStage.FINAL_OUTPUT,
        )

        assert result.action == GuardAction.REDACT
        assert "user@example.com" not in result.output_value
        assert token not in result.output_value
        assert {finding.rule_id for finding in result.findings} >= {"SD-001", "SD-015"}

    def test_block_mode_blocks_pii(self):
        guard = Guard(config=GuardConfig(sensitive_data_mode=SensitiveDataMode.BLOCK))

        result = guard.check("Email user@example.com", GuardStage.FINAL_OUTPUT)

        assert result.action == GuardAction.BLOCK

    def test_allow_mode_reports_without_transforming(self):
        guard = Guard(config=GuardConfig(sensitive_data_mode=SensitiveDataMode.ALLOW))
        token = _github_token()

        result = guard.check(token, GuardStage.FINAL_OUTPUT)

        assert result.action == GuardAction.ALLOW
        assert result.output_value == token
        assert result.findings

    def test_scans_beyond_previous_fifty_thousand_character_limit(self):
        value = "a" * 60_000 + " user@example.com"

        result = EmailRule().evaluate(value, _context())

        assert result.finding is not None
        assert result.finding.rule_id == "SD-001"
        assert result.transformed_value is not None
        assert "user@example.com" not in result.transformed_value


def test_sensitive_findings_do_not_retain_other_secrets():
    token = _github_token()
    decision = ProviderApiTokenRule().evaluate(
        f"user@example.com {token}",
        _context(),
    )

    assert decision.finding is not None
    serialized_finding = decision.finding.model_dump_json()
    assert token not in serialized_finding
    assert "user@example.com" not in serialized_finding
