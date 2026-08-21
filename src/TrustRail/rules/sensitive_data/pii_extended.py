"""Extended PII detection rules: SSN, IBAN, passport, driver's license."""

from __future__ import annotations

import re
from typing import ClassVar

from aiRail.models.core import GuardContext, GuardDecision
from aiRail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from aiRail.rules.base import BaseRule, registry

# ── US Social Security Number ─────────────────────────────────────────────────
# Format: XXX-XX-XXXX or XXXXXXXXX
# Excludes invalid ranges: 000-xx-xxxx, 666-xx-xxxx, 9xx-xx-xxxx
# Requires context keyword nearby to cut false positives on plain 9-digit numbers.

_SSN_BARE_RE = re.compile(
    r"(?<!\d)"
    r"(?!000|666|9\d{2})\d{3}"
    r"[- ]?"
    r"(?!00)\d{2}"
    r"[- ]?"
    r"(?!0000)\d{4}"
    r"(?!\d)"
)

_SSN_CONTEXT_RE = re.compile(
    r"\b(?:ssn|social\s+security(?:\s+number)?|sin\b)",
    re.IGNORECASE,
)

# ── IBAN ──────────────────────────────────────────────────────────────────────
# Format: CC##BBAN — 2 alpha country code + 2 check digits + up to 30 alphanum
# Must be 15–34 chars total.

_IBAN_RE = re.compile(
    r"\b"
    r"(?:AD|AE|AL|AT|AZ|BA|BE|BG|BH|BR|BY|CH|CR|CY|CZ|DE|DK|DO|EE|EG|ES|FI|"
    r"FO|FR|GB|GE|GI|GL|GR|GT|HR|HU|IE|IL|IS|IT|JO|KW|KZ|LB|LC|LI|LT|LU|LV|"
    r"MC|MD|ME|MK|MR|MT|MU|NL|NO|PK|PL|PS|PT|QA|RO|RS|SA|SE|SI|SK|SM|TN|TR|"
    r"UA|VA|VG|XK)"
    r"\d{2}"
    r"[A-Z0-9]{11,30}"
    r"\b"
)

# ── Passport number ───────────────────────────────────────────────────────────
# Require an explicit keyword context to reduce false positives on short IDs.
# Covered formats: US (9 digits), UK (A12345678), many EU (AB1234567), generic.

_PASSPORT_BARE_RE = re.compile(
    r"\b"
    r"(?:[A-Z]{1,2}\d{6,9}|\d{9})"
    r"\b"
)

_PASSPORT_CONTEXT_RE = re.compile(
    r"\b(?:passport(?:\s+(?:number|no|#|num))?|travel\s+document)",
    re.IGNORECASE,
)

# ── Driver's licence ──────────────────────────────────────────────────────────
# Heuristic for common formats; requires context keyword to limit false positives.

_DL_BARE_RE = re.compile(r"\b[A-Z]{1,2}\d{5,8}[A-Z0-9]{0,3}\b")

_DL_CONTEXT_RE = re.compile(
    r"\b(?:driver(?:'?s)?\s+licen[sc]e|driving\s+licen[sc]e|dl\s+(?:number|no|#))",
    re.IGNORECASE,
)

_CONTEXT_WINDOW = 120  # chars to scan around a match for context keywords


def _has_context(text: str, match_start: int, match_end: int, ctx_re: re.Pattern[str]) -> bool:
    """Check whether a context keyword appears within the window around the match."""
    lo = max(0, match_start - _CONTEXT_WINDOW)
    hi = min(len(text), match_end + _CONTEXT_WINDOW)
    return bool(ctx_re.search(text[lo:hi]))


def _make_redacted(text: str, pattern: re.Pattern[str], placeholder: str) -> str:
    return pattern.sub(placeholder, text)


@registry.register
class SsnRule(BaseRule):
    """Detects US Social Security Numbers (SSN) in text.

    Matches both formatted (XXX-XX-XXXX) and unformatted (XXXXXXXXX) SSNs.
    Requires a nearby context keyword (``ssn``, ``social security``) for bare
    9-digit matches to avoid flagging random numeric sequences.
    """

    rule_id: ClassVar[str] = "SD-011"
    rule_name: ClassVar[str] = "SSN"
    category: ClassVar[RuleCategory] = RuleCategory.SENSITIVE_DATA
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.REDACT
    description: ClassVar[str] = "Detects US Social Security Numbers."
    owasp: ClassVar[list[str]] = ["LLM06"]

    def __init__(self, enabled: bool = True, redact_placeholder: str = "[SSN]") -> None:
        super().__init__(enabled=enabled)
        self.redact_placeholder = redact_placeholder

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for m in _SSN_BARE_RE.finditer(text):
            raw = m.group(0)
            # Formatted SSNs (with dashes/spaces) are unambiguous; bare digits need context
            is_formatted = "-" in raw or " " in raw
            if is_formatted or _has_context(text, m.start(), m.end(), _SSN_CONTEXT_RE):
                redacted = _make_redacted(text, _SSN_BARE_RE, self.redact_placeholder)
                finding = self._finding(
                    "SSN detected",
                    severity=Severity.CRITICAL,
                    offset_start=m.start(),
                    offset_end=m.end(),
                )
                finding.redacted_value = redacted
                return GuardDecision(
                    action=GuardAction.REDACT,
                    finding=finding,
                    transformed_value=redacted,
                    rule_id=self.rule_id,
                )
        return self._allow()


@registry.register
class IbanRule(BaseRule):
    """Detects International Bank Account Numbers (IBAN) in text.

    Matches IBANs starting with a recognised two-letter country code followed
    by two check digits and up to 30 alphanumeric BBAN characters.
    """

    rule_id: ClassVar[str] = "SD-012"
    rule_name: ClassVar[str] = "IBAN"
    category: ClassVar[RuleCategory] = RuleCategory.SENSITIVE_DATA
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.REDACT
    description: ClassVar[str] = "Detects International Bank Account Numbers (IBAN)."
    owasp: ClassVar[list[str]] = ["LLM06"]

    def __init__(self, enabled: bool = True, redact_placeholder: str = "[IBAN]") -> None:
        super().__init__(enabled=enabled)
        self.redact_placeholder = redact_placeholder

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        m = _IBAN_RE.search(text)
        if m:
            redacted = _make_redacted(text, _IBAN_RE, self.redact_placeholder)
            finding = self._finding(
                "IBAN detected",
                severity=Severity.CRITICAL,
                offset_start=m.start(),
                offset_end=m.end(),
            )
            finding.redacted_value = redacted
            return GuardDecision(
                action=GuardAction.REDACT,
                finding=finding,
                transformed_value=redacted,
                rule_id=self.rule_id,
            )
        return self._allow()


@registry.register
class PassportNumberRule(BaseRule):
    """Detects passport numbers in text.

    Requires an adjacent context keyword (``passport``, ``travel document``)
    to reduce false positives from other alphanumeric identifiers.
    """

    rule_id: ClassVar[str] = "SD-013"
    rule_name: ClassVar[str] = "Passport Number"
    category: ClassVar[RuleCategory] = RuleCategory.SENSITIVE_DATA
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.REDACT
    description: ClassVar[str] = "Detects passport numbers with context keywords."
    owasp: ClassVar[list[str]] = ["LLM06"]

    def __init__(self, enabled: bool = True, redact_placeholder: str = "[PASSPORT]") -> None:
        super().__init__(enabled=enabled)
        self.redact_placeholder = redact_placeholder

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for m in _PASSPORT_BARE_RE.finditer(text):
            if _has_context(text, m.start(), m.end(), _PASSPORT_CONTEXT_RE):
                redacted = _make_redacted(text, _PASSPORT_BARE_RE, self.redact_placeholder)
                finding = self._finding(
                    "Passport number detected",
                    severity=Severity.CRITICAL,
                    offset_start=m.start(),
                    offset_end=m.end(),
                )
                finding.redacted_value = redacted
                return GuardDecision(
                    action=GuardAction.REDACT,
                    finding=finding,
                    transformed_value=redacted,
                    rule_id=self.rule_id,
                )
        return self._allow()


@registry.register
class DriversLicenseRule(BaseRule):
    """Detects driver's licence numbers in text.

    Uses a heuristic alphanumeric pattern and requires an adjacent context
    keyword (``driver's license``, ``driving licence``, ``DL number``) to
    avoid false positives on other short identifiers.
    """

    rule_id: ClassVar[str] = "SD-014"
    rule_name: ClassVar[str] = "Driver's License"
    category: ClassVar[RuleCategory] = RuleCategory.SENSITIVE_DATA
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.REDACT
    description: ClassVar[str] = "Detects driver's licence numbers with context keywords."
    owasp: ClassVar[list[str]] = ["LLM06"]

    def __init__(self, enabled: bool = True, redact_placeholder: str = "[DRIVERS_LICENSE]") -> None:
        super().__init__(enabled=enabled)
        self.redact_placeholder = redact_placeholder

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for m in _DL_BARE_RE.finditer(text):
            if _has_context(text, m.start(), m.end(), _DL_CONTEXT_RE):
                redacted = _make_redacted(text, _DL_BARE_RE, self.redact_placeholder)
                finding = self._finding(
                    "Driver's licence number detected",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                )
                finding.redacted_value = redacted
                return GuardDecision(
                    action=GuardAction.REDACT,
                    finding=finding,
                    transformed_value=redacted,
                    rule_id=self.rule_id,
                )
        return self._allow()
