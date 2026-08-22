"""Invisible Unicode channel sanitization for prompt-injection defense."""

from __future__ import annotations

from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.normalization import strip_invisible_unicode
from trustrail.rules.base import BaseRule, registry


@registry.register
class InvisibleUnicodeRule(BaseRule):
    """Strip Unicode characters that can hide instructions or exfiltrate bytes."""

    rule_id: ClassVar[str] = "PI-016"
    rule_name: ClassVar[str] = "Invisible Unicode Channel Sanitization"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.NORMALIZE
    default_severity: ClassVar[Severity] = Severity.LOW
    default_action: ClassVar[GuardAction] = GuardAction.TRANSFORM
    description: ClassVar[str] = (
        "Strips zero-width, bidirectional control, tag, and variation-selector characters."
    )
    owasp: ClassVar[list[str]] = ["LLM01"]

    def __init__(
        self,
        enabled: bool = True,
        *,
        strip_bidi_controls: bool = True,
        strip_zero_width: bool = True,
        strip_tag_chars: bool = True,
        strip_variation_selectors: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.strip_bidi_controls = strip_bidi_controls
        self.strip_zero_width = strip_zero_width
        self.strip_tag_chars = strip_tag_chars
        self.strip_variation_selectors = strip_variation_selectors

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        sanitized, counts = strip_invisible_unicode(
            value,
            strip_bidi_controls=self.strip_bidi_controls,
            strip_zero_width=self.strip_zero_width,
            strip_tag_chars=self.strip_tag_chars,
            strip_variation_selectors=self.strip_variation_selectors,
        )
        if not counts:
            return self._allow()

        higher_risk_channels = {"unicode_tag_chars", "variation_selectors"}
        severity = Severity.MEDIUM if higher_risk_channels.intersection(counts) else Severity.LOW
        finding = self._finding(
            "Invisible Unicode channel removed",
            severity=severity,
            confidence=1.0,
            removed_count=sum(counts.values()),
            channel_types=sorted(counts),
            counts=counts,
        )
        return GuardDecision(
            action=GuardAction.TRANSFORM,
            finding=finding,
            transformed_value=sanitized,
            rule_id=self.rule_id,
        )
