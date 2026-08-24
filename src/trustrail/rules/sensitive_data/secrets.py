"""Secret and credential detection rules."""

from __future__ import annotations

import re
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.normalization.normalizer import _shannon_entropy
from trustrail.rules.base import BaseRule, registry

# ── Credit Card (with Luhn) ──────────────────────────────────────────────────

_CC_RE = re.compile(
    r"""
    (?<!\d)
    (?:
        4\d{3}|                  # Visa
        5[1-5]\d{2}|             # Mastercard
        3[47]\d{2}|              # Amex
        6(?:011|5\d\d)           # Discover
    )
    [\s\-]?
    \d{4}[\s\-]?\d{4}[\s\-]?\d{2,4}
    (?!\d)
    """,
    re.VERBOSE,
)


def _luhn_valid(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@registry.register
class PaymentCardRule(BaseRule):
    """Detects payment card numbers with Luhn validation."""

    rule_id: ClassVar[str] = "SD-004"
    rule_name: ClassVar[str] = "Payment Card Number"
    category: ClassVar[RuleCategory] = RuleCategory.SENSITIVE_DATA
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects payment card numbers with Luhn validation."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def __init__(self, enabled: bool = True, redact_placeholder: str = "[PAYMENT_CARD]") -> None:
        super().__init__(enabled=enabled)
        self.redact_placeholder = redact_placeholder

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value
        for m in _CC_RE.finditer(text):
            candidate = re.sub(r"[\s\-]", "", m.group(0))
            if _luhn_valid(candidate):
                redacted = _CC_RE.sub(self.redact_placeholder, text)
                finding = self._finding(
                    "Payment card number detected",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                )
                return GuardDecision(
                    action=GuardAction.BLOCK,
                    finding=finding,
                    transformed_value=redacted,
                    rule_id=self.rule_id,
                )
        return self._allow()


# ── JWT Token ─────────────────────────────────────────────────────────────────

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")


@registry.register
class JwtTokenRule(BaseRule):
    """Detects JWT tokens in text."""

    rule_id: ClassVar[str] = "SD-005"
    rule_name: ClassVar[str] = "JWT Token"
    category: ClassVar[RuleCategory] = RuleCategory.SECRET
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects JWT tokens."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value
        m = _JWT_RE.search(text)
        if m:
            redacted = _JWT_RE.sub("[JWT_TOKEN]", text)
            finding = self._finding(
                "JWT token detected",
                offset_start=m.start(),
                offset_end=m.end(),
            )
            return GuardDecision(
                action=GuardAction.BLOCK,
                finding=finding,
                transformed_value=redacted,
                rule_id=self.rule_id,
            )
        return self._allow()


# ── Bearer Token ──────────────────────────────────────────────────────────────

_BEARER_RE = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{20,}={0,2})\b")

_API_KEY_RE = re.compile(
    r"""
    (?i)
    (?:api[_\-]?key|apikey|api_token|access[_\-]?token|auth[_\-]?token)
    \s*[=:]\s*
    ['"]?
    ([A-Za-z0-9\-._~+/]{20,}={0,2})
    ['"]?
    """,
    re.VERBOSE,
)


@registry.register
class BearerTokenRule(BaseRule):
    """Detects Bearer tokens and API keys in text."""

    rule_id: ClassVar[str] = "SD-006"
    rule_name: ClassVar[str] = "Bearer/API Token"
    category: ClassVar[RuleCategory] = RuleCategory.SECRET
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects Bearer tokens and API keys."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value
        for pattern, label in [(_BEARER_RE, "Bearer token"), (_API_KEY_RE, "API key")]:
            m = pattern.search(text)
            if m:
                redacted = pattern.sub(
                    lambda _m: _m.group(0).replace(_m.group(1), "[REDACTED]"),
                    text,
                )
                finding = self._finding(
                    f"{label} detected",
                    offset_start=m.start(),
                    offset_end=m.end(),
                )
                return GuardDecision(
                    action=GuardAction.BLOCK,
                    finding=finding,
                    transformed_value=redacted,
                    rule_id=self.rule_id,
                )
        return self._allow()


# ── AWS Keys ──────────────────────────────────────────────────────────────────

_AWS_ACCESS_KEY_RE = re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")
_AWS_SECRET_RE = re.compile(
    r"""
    (?i)
    (?:aws[_\-]?secret|aws[_\-]?access[_\-]?key[_\-]?secret)
    \s*[=:]\s*
    ['"]?([A-Za-z0-9/+]{40})['"]?
    """,
    re.VERBOSE,
)

# GCP service account key indicator
_GCP_SA_RE = re.compile(r'"type"\s*:\s*"service_account"', re.IGNORECASE)

# Azure connection string
_AZURE_CONN_RE = re.compile(
    r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}",
    re.IGNORECASE,
)


@registry.register
class AwsKeyRule(BaseRule):
    """Detects AWS access keys and secrets."""

    rule_id: ClassVar[str] = "SD-007"
    rule_name: ClassVar[str] = "AWS Credential"
    category: ClassVar[RuleCategory] = RuleCategory.SECRET
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects AWS access keys, secrets, GCP SA keys, Azure connections."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value
        for pattern, label, placeholder in [
            (_AWS_ACCESS_KEY_RE, "AWS access key", "[AWS_ACCESS_KEY]"),
            (_AWS_SECRET_RE, "AWS secret key", "[AWS_SECRET_KEY]"),
            (_GCP_SA_RE, "GCP service account key", "[GCP_SERVICE_ACCOUNT]"),
            (_AZURE_CONN_RE, "Azure connection string", "[AZURE_CONNECTION]"),
        ]:
            m = pattern.search(text)
            if m:
                redacted = placeholder if pattern is _GCP_SA_RE else pattern.sub(placeholder, text)
                finding = self._finding(
                    f"{label} detected",
                    severity=Severity.CRITICAL,
                    offset_start=m.start(),
                    offset_end=m.end(),
                )
                return GuardDecision(
                    action=GuardAction.BLOCK,
                    finding=finding,
                    transformed_value=redacted,
                    rule_id=self.rule_id,
                )
        return self._allow()


# ── Private Keys ──────────────────────────────────────────────────────────────

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN\s+(?:(?:RSA|EC|DSA|OPENSSH)\s+)?PRIVATE\s+KEY-----"
    r"[\s\S]*?(?:-----END\s+(?:(?:RSA|EC|DSA|OPENSSH)\s+)?PRIVATE\s+KEY-----|$)"
)


@registry.register
class PrivateKeyRule(BaseRule):
    """Detects private key material (RSA, EC, DSA, OpenSSH)."""

    rule_id: ClassVar[str] = "SD-008"
    rule_name: ClassVar[str] = "Private Key"
    category: ClassVar[RuleCategory] = RuleCategory.SECRET
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects private key material."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value
        m = _PRIVATE_KEY_RE.search(text)
        if m:
            finding = self._finding(
                "Private key material detected",
                severity=Severity.CRITICAL,
                offset_start=m.start(),
                offset_end=m.end(),
            )
            return GuardDecision(
                action=GuardAction.BLOCK,
                finding=finding,
                transformed_value=_PRIVATE_KEY_RE.sub("[PRIVATE_KEY]", text),
                rule_id=self.rule_id,
            )
        return self._allow()


# ── Database URLs ─────────────────────────────────────────────────────────────

_DB_URL_RE = re.compile(
    r"""
    (?i)
    (?:postgresql|postgres|mysql|mongodb|redis|mssql|sqlite|mariadb|oracle)
    \+?
    (?:\w+)?
    ://
    (?:[^:@\s]+:[^@\s]+@)     # user:password@
    [^\s'",;)]+
    """,
    re.VERBOSE,
)


@registry.register
class DatabaseUrlRule(BaseRule):
    """Detects database connection strings/URLs containing credentials."""

    rule_id: ClassVar[str] = "SD-009"
    rule_name: ClassVar[str] = "Database URL with Credentials"
    category: ClassVar[RuleCategory] = RuleCategory.SECRET
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects database connection strings containing credentials."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value
        m = _DB_URL_RE.search(text)
        if m:
            redacted = _DB_URL_RE.sub("[DB_URL_REDACTED]", text)
            finding = self._finding(
                "Database URL with credentials detected",
                severity=Severity.CRITICAL,
                offset_start=m.start(),
                offset_end=m.end(),
            )
            return GuardDecision(
                action=GuardAction.BLOCK,
                finding=finding,
                transformed_value=redacted,
                rule_id=self.rule_id,
            )
        return self._allow()


# ── High Entropy Secret ───────────────────────────────────────────────────────

_HIGH_ENTROPY_CANDIDATE = re.compile(
    r"""
    (?i)
    (?:secret|password|passwd|pwd|token|key|credential|auth|private|api)
    \s*[=:]\s*
    ['"]?
    ([A-Za-z0-9+/\-_.~!@#$%^&*]{20,80})
    ['"]?
    """,
    re.VERBOSE,
)

_ENTROPY_THRESHOLD = 4.5
_MIN_SECRET_LENGTH = 20


@registry.register
class HighEntropySecretRule(BaseRule):
    """Detects high-entropy strings that look like secrets."""

    rule_id: ClassVar[str] = "SD-010"
    rule_name: ClassVar[str] = "High Entropy Secret"
    category: ClassVar[RuleCategory] = RuleCategory.SECRET
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = "Detects high-entropy strings assigned to secret-named variables."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value
        for m in _HIGH_ENTROPY_CANDIDATE.finditer(text):
            candidate = m.group(1)
            if (
                len(candidate) >= _MIN_SECRET_LENGTH
                and _shannon_entropy(candidate) >= _ENTROPY_THRESHOLD
            ):
                redacted = _HIGH_ENTROPY_CANDIDATE.sub(
                    lambda match: match.group(0).replace(match.group(1), "[REDACTED]"),
                    text,
                )
                finding = self._finding(
                    "High-entropy secret-like value detected",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    entropy=round(_shannon_entropy(candidate), 2),
                )
                return GuardDecision(
                    action=GuardAction.WARN,
                    finding=finding,
                    transformed_value=redacted,
                    rule_id=self.rule_id,
                )
        return self._allow()


# ── Named credentials ────────────────────────────────────────────────────────

_NAMED_CREDENTIAL_RE = re.compile(
    r"""
    \b(?:password|passwd|pwd|client[_-]?secret|consumer[_-]?secret|private[_-]?token)\b
    \s*[=:]\s*
    ['"]?
    ([^\s'",;}{]{8,128})
    ['"]?
    """,
    re.IGNORECASE | re.VERBOSE,
)


@registry.register
class NamedCredentialRule(BaseRule):
    """Detect password and client-secret assignment patterns."""

    rule_id: ClassVar[str] = "SD-016"
    rule_name: ClassVar[str] = "Named Credential"
    category: ClassVar[RuleCategory] = RuleCategory.SECRET
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects values assigned to password and secret fields."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        match = _NAMED_CREDENTIAL_RE.search(value)
        if match is None:
            return self._allow()

        redacted = _NAMED_CREDENTIAL_RE.sub(
            lambda item: item.group(0).replace(item.group(1), "[REDACTED]"),
            value,
        )
        finding = self._finding(
            "Named credential detected",
            offset_start=match.start(),
            offset_end=match.end(),
        )
        return GuardDecision(
            action=GuardAction.BLOCK,
            finding=finding,
            transformed_value=redacted,
            rule_id=self.rule_id,
        )


# ── Provider API tokens ──────────────────────────────────────────────────────

_PROVIDER_TOKEN_PATTERNS = (
    re.compile(
        r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})"
    ),
    re.compile(r"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{16,}"),
    re.compile(r"(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    re.compile(r"(?<![A-Za-z0-9])sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
    re.compile(r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
)


@registry.register
class ProviderApiTokenRule(BaseRule):
    """Detect common provider-specific API token formats."""

    rule_id: ClassVar[str] = "SD-015"
    rule_name: ClassVar[str] = "Provider API Token"
    category: ClassVar[RuleCategory] = RuleCategory.SECRET
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects common hosted-service API token formats."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        first_match: re.Match[str] | None = None
        redacted = value
        match_count = 0
        for pattern in _PROVIDER_TOKEN_PATTERNS:
            matches = list(pattern.finditer(redacted))
            if not matches:
                continue
            if first_match is None:
                first_match = matches[0]
            match_count += len(matches)
            redacted = pattern.sub("[API_TOKEN]", redacted)

        if first_match is None:
            return self._allow()

        finding = self._finding(
            "Provider API token detected",
            offset_start=first_match.start(),
            offset_end=first_match.end(),
            match_count=match_count,
        )
        return GuardDecision(
            action=GuardAction.BLOCK,
            finding=finding,
            transformed_value=redacted,
            rule_id=self.rule_id,
        )
