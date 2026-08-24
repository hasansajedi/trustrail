"""Detection of application-defined private context in generated text."""

from __future__ import annotations

import re
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.models.sensitive_data import ProtectedData
from trustrail.rules.base import BaseRule

_SENTENCE_BOUNDARY_RE = re.compile(r"(?<=[.!?])\s+|[\r\n]+")


def _fragments(item: ProtectedData) -> list[str]:
    """Return bounded, useful verbatim fragments without persisting them."""
    candidates = [item.value.strip(), *(_SENTENCE_BOUNDARY_RE.split(item.value))]
    fragments = {
        candidate.strip()
        for candidate in candidates
        if len(candidate.strip()) >= item.min_match_chars
    }
    return sorted(fragments, key=len, reverse=True)


def _flexible_whitespace_pattern(fragment: str, *, case_sensitive: bool) -> re.Pattern[str]:
    parts = re.split(r"\s+", fragment)
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile(r"\s+".join(re.escape(part) for part in parts), flags)


class ProtectedDataDisclosureRule(BaseRule):
    """Detect verbatim disclosure of caller-supplied private context."""

    rule_id: ClassVar[str] = "SD-017"
    rule_name: ClassVar[str] = "Protected Data Disclosure"
    category: ClassVar[RuleCategory] = RuleCategory.SENSITIVE_DATA
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects generated text copied from protected context."
    owasp: ClassVar[list[str]] = ["LLM02:2025"]

    def __init__(self, protected_data: list[ProtectedData]) -> None:
        super().__init__()
        self._protected_data = protected_data

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        patterns: list[re.Pattern[str]] = []
        for item in self._protected_data:
            patterns.extend(
                _flexible_whitespace_pattern(fragment, case_sensitive=item.case_sensitive)
                for fragment in _fragments(item)
            )

        first_match: re.Match[str] | None = None
        match_count = 0
        redacted = value
        for pattern in patterns:
            matches = list(pattern.finditer(redacted))
            if not matches:
                continue
            if first_match is None:
                first_match = matches[0]
            match_count += len(matches)
            redacted = pattern.sub("[PROTECTED_DATA]", redacted)

        if first_match is None:
            return self._allow()

        finding = self._finding(
            "Protected context reproduced in output",
            offset_start=first_match.start(),
            offset_end=first_match.end(),
            protected_item_count=len(self._protected_data),
            match_count=match_count,
        )
        return GuardDecision(
            action=GuardAction.BLOCK,
            finding=finding,
            transformed_value=redacted,
            rule_id=self.rule_id,
        )
