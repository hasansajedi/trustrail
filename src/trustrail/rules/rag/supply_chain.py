"""Supply-chain boundary rules — OWASP LLM03:2025."""

from __future__ import annotations

import re
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.rules.base import BaseRule, registry

# Instruction-injection patterns that may appear inside API / tool responses.
# Attackers embed these inside JSON values, HTML bodies, or plain-text responses
# to hijack the model's behaviour when the content is later used as LLM context.
_INJECTED_INSTRUCTION_RE = re.compile(
    r"""
    \b(?:
        # Classic "ignore previous instructions" pivot
        (?:ignore|disregard|forget|override|bypass)\s+
        (?:all\s+)?(?:previous|prior|above|your)\s+
        (?:instructions?|guidelines?|rules?|prompts?|constraints?)|

        # "new instructions:" / "new instructions: you are now..." style headers
        (?:new|updated|revised|replacement)\s+
        (?:instructions?|system\s+prompt|rules?|directives?)(?:\s*[:\-]|\s+you\s+are)|

        # "updated system prompt" variant without colon
        (?:updated|new|revised)\s+system\s+prompt|

        # disregard/ignore ... guidelines/rules (with or without "previous")
        (?:ignore|disregard|forget|override|bypass)\s+
        (?:all\s+)?(?:your\s+)?(?:prior\s+)?
        (?:instructions?|guidelines?|rules?|prompts?|constraints?)|

        # Role-reassignment inside response content
        (?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are))\s+
        (?:a\s+)?(?:different|new|unrestricted|jailbroken|evil|DAN)|

        # "from now on" instruction pivot
        (?:from\s+now\s+on|starting\s+(?:now|immediately))\s*,?\s*
        (?:you\s+(?:will|must|should)|always|never)\s
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


@registry.register
class ApiResponseIntegrityRule(BaseRule):
    """Detects injected LLM instructions embedded inside external API or tool responses.

    Supply chain attacks (OWASP LLM03:2025) plant prompt-injection payloads inside
    data that flows from third-party APIs into the LLM context. This rule scans
    tool/API responses for instruction-hijacking patterns before they are used.

    Apply this rule to content at the ``tool_response`` or ``external_content``
    guard stages.
    """

    rule_id: ClassVar[str] = "SC-001"
    rule_name: ClassVar[str] = "API Response Integrity"
    category: ClassVar[RuleCategory] = RuleCategory.RAG
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects prompt-injection payloads embedded in external API or tool responses."
    )
    owasp: ClassVar[list[str]] = ["LLM03:2025", "LLM01:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        match = _INJECTED_INSTRUCTION_RE.search(value)
        if match:
            return self._block(
                "Injected instruction detected in API response",
                severity=Severity.CRITICAL,
                offset_start=match.start(),
                offset_end=match.end(),
                match_length=len(match.group(0)),
            )
        return self._allow()
