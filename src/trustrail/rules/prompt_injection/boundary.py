"""Cross-boundary prompt-injection detection."""

from __future__ import annotations

from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.models.prompt import PromptSegment
from trustrail.rules.base import BaseRule, registry
from trustrail.rules.prompt_injection.advanced import MultilingualInjectionRule
from trustrail.rules.prompt_injection.direct import (
    DirectInjectionRule,
    JailbreakRule,
    SystemOverrideRule,
)
from trustrail.rules.prompt_injection.indirect import (
    EncodingObfuscationRule,
    IndirectInjectionRule,
    ToolManipulationRule,
)


@registry.register
class CrossBoundaryInjectionRule(BaseRule):
    """Detect an attack assembled from two separately safe prompt segments."""

    rule_id: ClassVar[str] = "PI-017"
    rule_name: ClassVar[str] = "Cross-boundary Prompt Injection"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects injection payloads assembled across separately labeled prompt segments."
    )
    owasp: ClassVar[tuple[str, ...]] = ("LLM01",)

    def __init__(self, enabled: bool = True, *, window_chars: int = 512) -> None:
        super().__init__(enabled=enabled)
        if window_chars < 32:
            raise ValueError("window_chars must be at least 32")
        self.window_chars = window_chars
        self._scanners: tuple[BaseRule, ...] = (
            DirectInjectionRule(),
            JailbreakRule(),
            SystemOverrideRule(),
            IndirectInjectionRule(),
            ToolManipulationRule(),
            EncodingObfuscationRule(),
            MultilingualInjectionRule(),
        )

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Allow unstructured text; callers must use ``evaluate_segments``."""
        return self._allow()

    def evaluate_segments(
        self,
        left: PromptSegment,
        right: PromptSegment,
        context: GuardContext,
    ) -> GuardDecision:
        """Evaluate content at the boundary between two labeled segments."""
        left_text = left.content[-self.window_chars :]
        right_text = right.content[: self.window_chars]

        for separator, candidate in (
            ("space", f"{left_text} {right_text}"),
            ("none", f"{left_text}{right_text}"),
        ):
            for scanner in self._scanners:
                if scanner.evaluate(left_text, context).action == GuardAction.BLOCK:
                    continue
                if scanner.evaluate(right_text, context).action == GuardAction.BLOCK:
                    continue
                if scanner.evaluate(candidate, context).action != GuardAction.BLOCK:
                    continue
                return self._block(
                    "Prompt injection assembled across content boundaries",
                    detector_rule_id=scanner.rule_id,
                    left_segment_id=left.segment_id,
                    left_source=left.source.value,
                    right_segment_id=right.segment_id,
                    right_source=right.source.value,
                    join_mode=separator,
                    left_characters_scanned=len(left_text),
                    right_characters_scanned=len(right_text),
                    left_truncated=len(left.content) > len(left_text),
                    right_truncated=len(right.content) > len(right_text),
                )

        return self._allow()
