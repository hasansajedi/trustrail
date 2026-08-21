"""Tests for extended PII rules: SSN, IBAN, passport, driver's licence."""

import pytest

from aiRail.models.core import GuardContext
from aiRail.models.enums import GuardAction, GuardStage
from aiRail.rules.sensitive_data.pii_extended import (
    DriversLicenseRule,
    IbanRule,
    PassportNumberRule,
    SsnRule,
)


def _ctx() -> GuardContext:
    return GuardContext(stage=GuardStage.LLM_RESPONSE)


class TestSsnRule:
    def test_detects_formatted_ssn(self):
        rule = SsnRule()
        result = rule.evaluate("My SSN is 123-45-6789.", _ctx())
        assert result.action == GuardAction.REDACT

    def test_detects_ssn_with_spaces(self):
        rule = SsnRule()
        result = rule.evaluate("SSN: 234 56 7890", _ctx())
        assert result.action == GuardAction.REDACT

    def test_detects_bare_ssn_with_context_keyword(self):
        rule = SsnRule()
        result = rule.evaluate("Social Security Number: 345678901", _ctx())
        assert result.action == GuardAction.REDACT

    def test_ignores_bare_number_without_context(self):
        rule = SsnRule()
        result = rule.evaluate("The order ID is 345678901.", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_excludes_invalid_ssn_starting_with_000(self):
        rule = SsnRule()
        result = rule.evaluate("SSN: 000-12-3456", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_excludes_invalid_ssn_starting_with_666(self):
        rule = SsnRule()
        result = rule.evaluate("SSN: 666-12-3456", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_excludes_invalid_ssn_starting_with_9xx(self):
        rule = SsnRule()
        result = rule.evaluate("SSN: 999-12-3456", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_redacted_value_replaces_ssn(self):
        rule = SsnRule()
        result = rule.evaluate("SSN: 123-45-6789 is private.", _ctx())
        assert result.transformed_value is not None
        assert "[SSN]" in result.transformed_value
        assert "123-45-6789" not in result.transformed_value

    def test_custom_placeholder(self):
        rule = SsnRule(redact_placeholder="[REDACTED]")
        result = rule.evaluate("My SSN is 234-56-7890.", _ctx())
        assert result.transformed_value is not None
        assert "[REDACTED]" in result.transformed_value


class TestIbanRule:
    @pytest.mark.parametrize(
        "text",
        [
            "IBAN: GB29NWBK60161331926819",
            "Please send to DE89370400440532013000",
            "Account: FR7630006000011234567890189",
            "NL91ABNA0417164300",
        ],
    )
    def test_detects_valid_ibans(self, text: str):
        rule = IbanRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.REDACT

    def test_redacts_iban_in_text(self):
        rule = IbanRule()
        result = rule.evaluate("Wire to GB29NWBK60161331926819 today.", _ctx())
        assert result.transformed_value is not None
        assert "[IBAN]" in result.transformed_value
        assert "GB29NWBK" not in result.transformed_value

    def test_ignores_unknown_country_code(self):
        rule = IbanRule()
        result = rule.evaluate("Account: ZZ12345678901234", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_ignores_short_alphanumeric(self):
        rule = IbanRule()
        result = rule.evaluate("Reference: US1234", _ctx())
        assert result.action == GuardAction.ALLOW


class TestPassportNumberRule:
    @pytest.mark.parametrize(
        "text",
        [
            "Passport number: A12345678",
            "My passport no AB1234567 expires next year.",
            "Travel document: 123456789",
            "Passport #B9876543 was issued in 2020.",
        ],
    )
    def test_detects_passport_with_context(self, text: str):
        rule = PassportNumberRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.REDACT

    def test_ignores_id_without_context(self):
        rule = PassportNumberRule()
        result = rule.evaluate("Reference A12345678 for your order.", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_redacts_passport_number(self):
        rule = PassportNumberRule()
        result = rule.evaluate("Passport: A12345678 is valid.", _ctx())
        assert result.transformed_value is not None
        assert "[PASSPORT]" in result.transformed_value


class TestDriversLicenseRule:
    @pytest.mark.parametrize(
        "text",
        [
            "Driver's license: AB123456",
            "DL number: CD7891234",
            "Driving licence AB123456 issued by DVLA.",
            "DL #EF987654 expires 2027.",
        ],
    )
    def test_detects_dl_with_context(self, text: str):
        rule = DriversLicenseRule()
        result = rule.evaluate(text, _ctx())
        assert result.action == GuardAction.REDACT

    def test_ignores_id_without_context(self):
        rule = DriversLicenseRule()
        result = rule.evaluate("Part number AB123456 is in stock.", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_redacts_dl_number(self):
        rule = DriversLicenseRule()
        result = rule.evaluate("Driver's license: AB123456 is valid.", _ctx())
        assert result.transformed_value is not None
        assert "[DRIVERS_LICENSE]" in result.transformed_value
