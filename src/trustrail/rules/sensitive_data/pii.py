"""PII detection rules: email, phone, IP address."""

from __future__ import annotations

import re
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.rules.base import BaseRule, registry

# ── Email ─────────────────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")


@registry.register
class EmailRule(BaseRule):
    """Detects email addresses in text."""

    rule_id: ClassVar[str] = "SD-001"
    rule_name: ClassVar[str] = "Email Address"
    category: ClassVar[RuleCategory] = RuleCategory.SENSITIVE_DATA
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.REDACT
    description: ClassVar[str] = "Detects email addresses."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def __init__(self, enabled: bool = True, redact_placeholder: str = "[EMAIL]") -> None:
        super().__init__(enabled=enabled)
        self.redact_placeholder = redact_placeholder

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value
        m = _EMAIL_RE.search(text)
        if m:
            # Redact all occurrences
            redacted = _EMAIL_RE.sub(self.redact_placeholder, text)
            finding = self._finding(
                "Email address detected",
                offset_start=m.start(),
                offset_end=m.end(),
            )
            return GuardDecision(
                action=GuardAction.REDACT,
                finding=finding,
                transformed_value=redacted,
                rule_id=self.rule_id,
            )
        return self._allow()


# ── Phone ─────────────────────────────────────────────────────────────────────

# Matches common international phone formats
_PHONE_RE = re.compile(
    r"""
    (?<!\d)                       # not preceded by digit
    (?:
        \+?1[-.\s]?               # optional country code +1
    )?
    (?:
        \(\d{3}\)[-.\s]?          # (XXX)
        |\d{3}[-.\s]              # XXX-
    )
    \d{3}[-.\s]?\d{4}             # XXX-XXXX
    (?!\d)                        # not followed by digit
    |
    \+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}  # international
    """,
    re.VERBOSE,
)


@registry.register
class PhoneRule(BaseRule):
    """Detects phone numbers in text."""

    rule_id: ClassVar[str] = "SD-002"
    rule_name: ClassVar[str] = "Phone Number"
    category: ClassVar[RuleCategory] = RuleCategory.SENSITIVE_DATA
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.REDACT
    description: ClassVar[str] = "Detects phone numbers in various international formats."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def __init__(self, enabled: bool = True, redact_placeholder: str = "[PHONE]") -> None:
        super().__init__(enabled=enabled)
        self.redact_placeholder = redact_placeholder

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value
        m = _PHONE_RE.search(text)
        if m:
            redacted = _PHONE_RE.sub(self.redact_placeholder, text)
            finding = self._finding(
                "Phone number detected",
                offset_start=m.start(),
                offset_end=m.end(),
            )
            return GuardDecision(
                action=GuardAction.REDACT,
                finding=finding,
                transformed_value=redacted,
                rule_id=self.rule_id,
            )
        return self._allow()


# ── IP Address ────────────────────────────────────────────────────────────────

_IPV4_RE = re.compile(
    r"""
    (?<![.\d])
    (?:
        (?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.
    ){3}
    (?:25[0-5]|2[0-4]\d|[01]?\d\d?)
    (?![.\d])
    """,
    re.VERBOSE,
)


@registry.register
class IpAddressRule(BaseRule):
    """Detects IPv4 addresses in text."""

    rule_id: ClassVar[str] = "SD-003"
    rule_name: ClassVar[str] = "IP Address"
    category: ClassVar[RuleCategory] = RuleCategory.SENSITIVE_DATA
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.LOW
    default_action: ClassVar[GuardAction] = GuardAction.WARN
    description: ClassVar[str] = "Detects IPv4 addresses."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value
        m = _IPV4_RE.search(text)
        if m:
            finding = self._finding(
                "IP address detected",
                severity=Severity.LOW,
                offset_start=m.start(),
                offset_end=m.end(),
            )
            return GuardDecision(
                action=GuardAction.WARN,
                finding=finding,
                transformed_value=_IPV4_RE.sub("[IP_ADDRESS]", text),
                rule_id=self.rule_id,
            )
        return self._allow()
