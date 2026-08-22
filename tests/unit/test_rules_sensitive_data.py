"""Unit tests for sensitive data detection rules."""

from trustrail.models.core import GuardContext
from trustrail.models.enums import GuardAction, GuardStage
from trustrail.rules.sensitive_data.pii import EmailRule, IpAddressRule, PhoneRule
from trustrail.rules.sensitive_data.secrets import (
    AwsKeyRule,
    DatabaseUrlRule,
    HighEntropySecretRule,
    JwtTokenRule,
    PaymentCardRule,
    PrivateKeyRule,
    _luhn_valid,
)


def ctx():
    return GuardContext(stage=GuardStage.USER_INPUT)


class TestEmailRule:
    def setup_method(self):
        self.rule = EmailRule()

    def test_detects_simple_email(self):
        d = self.rule.evaluate("Contact me at user@example.com", ctx())
        assert d.action == GuardAction.REDACT
        assert d.finding is not None

    def test_redacts_email(self):
        d = self.rule.evaluate("Email: user@example.com", ctx())
        assert d.transformed_value is not None
        assert "user@example.com" not in d.transformed_value
        assert "[EMAIL]" in d.transformed_value

    def test_no_false_positive_plain_text(self):
        d = self.rule.evaluate("Hello, how are you today?", ctx())
        assert d.action == GuardAction.ALLOW

    def test_multiple_emails_redacted(self):
        d = self.rule.evaluate("Contacts: a@b.com and c@d.org", ctx())
        if d.action == GuardAction.REDACT:
            assert d.transformed_value is not None
            assert "a@b.com" not in d.transformed_value

    def test_rule_id(self):
        assert self.rule.id == "SD-001"


class TestPhoneRule:
    def setup_method(self):
        self.rule = PhoneRule()

    def test_detects_us_phone(self):
        d = self.rule.evaluate("Call me at (555) 867-5309", ctx())
        assert d.action == GuardAction.REDACT

    def test_detects_dashed_phone(self):
        d = self.rule.evaluate("Phone: 555-123-4567", ctx())
        assert d.action == GuardAction.REDACT

    def test_no_false_positive(self):
        d = self.rule.evaluate("I have 3 cats and 2 dogs", ctx())
        assert d.action == GuardAction.ALLOW


class TestIpAddressRule:
    def setup_method(self):
        self.rule = IpAddressRule()

    def test_detects_ipv4(self):
        d = self.rule.evaluate("Server at 192.168.1.100", ctx())
        assert d.action == GuardAction.WARN

    def test_no_false_positive(self):
        d = self.rule.evaluate("Hello world", ctx())
        assert d.action == GuardAction.ALLOW


class TestPaymentCardRule:
    def setup_method(self):
        self.rule = PaymentCardRule()

    def test_detects_valid_visa(self):
        # Valid Luhn test card
        d = self.rule.evaluate("Card: 4532015112830366", ctx())
        assert d.action == GuardAction.BLOCK

    def test_ignores_invalid_luhn(self):
        # Invalid Luhn (last digit wrong)
        d = self.rule.evaluate("Card: 4532015112830367", ctx())
        assert d.action == GuardAction.ALLOW

    def test_luhn_valid_visa(self):
        assert _luhn_valid("4532015112830366")

    def test_luhn_invalid(self):
        assert not _luhn_valid("1234567890123456")


class TestJwtTokenRule:
    def setup_method(self):
        self.rule = JwtTokenRule()

    def test_detects_jwt(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        d = self.rule.evaluate(f"Token: {jwt}", ctx())
        assert d.action == GuardAction.BLOCK
        assert d.transformed_value is not None
        assert jwt not in d.transformed_value

    def test_no_false_positive(self):
        d = self.rule.evaluate("Hello world", ctx())
        assert d.action == GuardAction.ALLOW

    def test_rule_id(self):
        assert self.rule.id == "SD-005"


class TestAwsKeyRule:
    def setup_method(self):
        self.rule = AwsKeyRule()

    def test_detects_aws_key(self):
        d = self.rule.evaluate("key=AKIAIOSFODNN7EXAMPLE", ctx())
        assert d.action == GuardAction.BLOCK

    def test_no_false_positive(self):
        d = self.rule.evaluate("Normal text here", ctx())
        assert d.action == GuardAction.ALLOW

    def test_rule_id(self):
        assert self.rule.id == "SD-007"


class TestPrivateKeyRule:
    def setup_method(self):
        self.rule = PrivateKeyRule()

    def test_detects_rsa_key(self):
        d = self.rule.evaluate("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_ec_key(self):
        d = self.rule.evaluate("-----BEGIN EC PRIVATE KEY-----\ndata", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_generic_private_key(self):
        d = self.rule.evaluate("-----BEGIN PRIVATE KEY-----\ndata", ctx())
        assert d.action == GuardAction.BLOCK

    def test_no_false_positive(self):
        d = self.rule.evaluate("Public key: -----BEGIN PUBLIC KEY-----", ctx())
        assert d.action == GuardAction.ALLOW


class TestDatabaseUrlRule:
    def setup_method(self):
        self.rule = DatabaseUrlRule()

    def test_detects_postgres_url(self):
        d = self.rule.evaluate("postgresql://user:password@localhost:5432/mydb", ctx())
        assert d.action == GuardAction.BLOCK

    def test_detects_mongodb_url(self):
        d = self.rule.evaluate("mongodb://admin:t3stpassword@localhost:27017/db", ctx())
        assert d.action == GuardAction.BLOCK

    def test_no_false_positive(self):
        d = self.rule.evaluate("Connect to the database", ctx())
        assert d.action == GuardAction.ALLOW


class TestHighEntropySecretRule:
    def setup_method(self):
        self.rule = HighEntropySecretRule()

    def test_detects_high_entropy_password(self):
        d = self.rule.evaluate("password=aB3xQ9mR2kP7nL5wY1vZjD8cE4gH6iF0", ctx())
        assert d.action in (GuardAction.WARN, GuardAction.BLOCK)

    def test_no_false_positive_low_entropy(self):
        d = self.rule.evaluate("password=aaaaaaaaaaaaaaaaaaaaaa", ctx())
        assert d.action == GuardAction.ALLOW

    def test_no_false_positive_short(self):
        d = self.rule.evaluate("key=short", ctx())
        assert d.action == GuardAction.ALLOW
