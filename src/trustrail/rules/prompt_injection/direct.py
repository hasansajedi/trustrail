"""Direct prompt injection and jailbreak detection rules.

All patterns are pre-compiled and designed to avoid catastrophic backtracking.
"""

from __future__ import annotations

import re
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.normalization.normalizer import TextNormalizer
from trustrail.rules.base import BaseRule, registry

_normalizer = TextNormalizer()

# ── Patterns (all pre-compiled, no catastrophic backtracking) ─────────────────

# Instruction override patterns
_OVERRIDE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"ignore\s+(?:all\s+|the\s+)?(?:previous|above|prior|earlier)\s+"
        r"(?:instructions?|context|rules?|constraints?|guidelines?|prompt)",
        re.IGNORECASE,
    ),
    re.compile(
        r"disregard\s+(?:the\s+|all\s+|your\s+)?(?:previous|prior|above)\s+"
        r"(?:instructions?|prompt|text)",
        re.IGNORECASE,
    ),
    re.compile(
        r"forget\s+(?:everything|all\s+(?:previous|prior|of\s+the)?\s*(?:i|you|we|this|above)?|"
        r"all\s+previous|all\s+prior|all\s+of\s+the|all)\s*"
        r"(?:(?:i|you|we)\s+)?(?:said|told|discussed|context|instructions?|history|conversation)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"override\s+(?:your\s+)?(?:previous\s+)?(?:instructions?|directives?|rules?|safety)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:bypass|circumvent|skip)\s+(?:all\s+|the\s+|your\s+)?(?:safety|guardrail|filter|restriction|policy|rules?|guidelines?|constraint)",
        re.IGNORECASE,
    ),
    re.compile(
        r"your\s+(?:real|true|actual|hidden)\s+(?:instructions?|purpose|goal|directive)",
        re.IGNORECASE,
    ),
    re.compile(
        r"new\s+(?:system\s+)?(?:prompt|instruction|directive|command)",
        re.IGNORECASE,
    ),
]

# Pseudo-system injection markers
_SYSTEM_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"\[system\]", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"#{1,3}\s*(?:system|instruction|directive)", re.IGNORECASE),
    re.compile(r"<\s*/?(?:INST|SYS|s|\/s)\s*>"),
    re.compile(r"\|\s*(?:system|begin\s*of\s*text|end\s*of\s*text)\s*\|", re.IGNORECASE),
    re.compile(r"<\s*\|?\s*(?:im_start|im_end)\s*\|?\s*>", re.IGNORECASE),
]

# Jailbreak persona patterns
_JAILBREAK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"you\s+are\s+now\s+(?:in\s+)?(?:developer|jailbreak|admin|god|unrestricted|DAN|evil|"
        r"chaos|anarchy|unfiltered)\s*(?:mode|version)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"act\s+as\s+(?:a\s+|an\s+)?(?:different|new|unrestricted|evil|malicious|"
        r"unethical|harmful|dangerous)",
        re.IGNORECASE,
    ),
    re.compile(
        r"new\s+(?:persona|personality|character|role|identity)\s*[:=]",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bDAN\b.*?(?:Do\s+Anything\s+Now|jailbreak|no\s+restrictions?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"pretend\s+(?:you\s+(?:are|have\s+no|can\s+do\s+anything)|there\s+(?:are\s+no|is\s+no))\s*"
        r"(?:rules?|restrictions?|limits?|guidelines?|filters?|training|ethical|constraints?|safety)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:enable|activate|switch\s+on)\s+(?:developer|debug|god|unrestricted|DAN)\s*mode",
        re.IGNORECASE,
    ),
    re.compile(
        r"without\s+(?:any\s+)?(?:ethical\s+)?(?:restrictions?|filters?|limitations?|guardrails?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:roleplay|role-play|role\s+play)\s+as\s+(?:an?\s+)?(?:AI|assistant|bot)\s+"
        r"(?:that|who|which)\s+(?:has\s+no|ignores?|bypasses?|can\s+do\s+anything)",
        re.IGNORECASE,
    ),
]


@registry.register
class DirectInjectionRule(BaseRule):
    """Detects direct prompt injection — instruction override attempts."""

    rule_id: ClassVar[str] = "PI-001"
    rule_name: ClassVar[str] = "Direct Prompt Injection"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    owasp: ClassVar[list[str]] = ["LLM01"]
    description: ClassVar[str] = (
        "Detects attempts to override, ignore, or bypass system instructions."
    )

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        # Limit processing length
        text = value[:10_000]

        # Try both original and normalized
        result = _normalizer.normalize(text)
        candidates = [result.normalized, text] if result.was_obfuscated else [text]

        for candidate in candidates:
            for pattern in _OVERRIDE_PATTERNS:
                m = pattern.search(candidate)
                if m:
                    return self._block(
                        "Prompt injection detected: instruction override attempt",
                        offset_start=m.start(),
                        offset_end=m.end(),
                        obfuscated=result.was_obfuscated,
                        signals=result.signals,
                    )

        for candidate in candidates:
            for pattern in _SYSTEM_MARKERS:
                m = pattern.search(candidate)
                if m:
                    return self._block(
                        "Prompt injection detected: system marker injection",
                        offset_start=m.start(),
                        offset_end=m.end(),
                        obfuscated=result.was_obfuscated,
                    )

        # Check for base64-encoded injection
        if result.was_obfuscated or _normalizer.is_likely_base64(text):
            payloads = _normalizer.extract_base64_payloads(text)
            for payload in payloads:
                for pattern in _OVERRIDE_PATTERNS + _SYSTEM_MARKERS:
                    m = pattern.search(payload)
                    if m:
                        return self._block(
                            "Prompt injection detected: base64-encoded injection attempt",
                            confidence=0.9,
                        )

        return self._allow()


@registry.register
class JailbreakRule(BaseRule):
    """Detects jailbreak attempts — persona manipulation and restriction bypass."""

    rule_id: ClassVar[str] = "PI-002"
    rule_name: ClassVar[str] = "Jailbreak Detection"
    category: ClassVar[RuleCategory] = RuleCategory.JAILBREAK
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects jailbreak attempts including DAN, persona manipulation, and "
        "restriction bypass patterns."
    )

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:10_000]
        result = _normalizer.normalize(text)
        candidates = [result.normalized, text] if result.was_obfuscated else [text]

        for candidate in candidates:
            for pattern in _JAILBREAK_PATTERNS:
                m = pattern.search(candidate)
                if m:
                    return self._block(
                        "Jailbreak attempt detected: persona/restriction manipulation",
                        offset_start=m.start(),
                        offset_end=m.end(),
                        obfuscated=result.was_obfuscated,
                    )

        return self._allow()


@registry.register
class SystemOverrideRule(BaseRule):
    """Detects attempts to inject new system prompts or hijack the conversation context."""

    rule_id: ClassVar[str] = "PI-003"
    rule_name: ClassVar[str] = "System Prompt Override"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects attempts to inject new system prompts or override the conversation context."
    )

    _SYSTEM_INJECT: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"---+\s*system\s*---+", re.IGNORECASE),
        re.compile(r"===+\s*system\s*===+", re.IGNORECASE),
        re.compile(r"SYSTEM\s*PROMPT\s*:", re.IGNORECASE),
        re.compile(r"SYSTEM\s*INSTRUCTION\s*:", re.IGNORECASE),
        re.compile(r"<\s*system\s*>[\s\S]{0,500}<\s*/system\s*>", re.IGNORECASE),
        re.compile(r"<\s*prompt\s*>[\s\S]{0,500}<\s*/prompt\s*>", re.IGNORECASE),
        re.compile(r"\{\{\s*system\s*\}\}", re.IGNORECASE),
        re.compile(r"\[\[\s*system\s*\]\]", re.IGNORECASE),
    ]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:10_000]
        result = _normalizer.normalize(text)
        candidates = [result.normalized, text] if result.was_obfuscated else [text]

        for candidate in candidates:
            for pattern in self._SYSTEM_INJECT:
                m = pattern.search(candidate)
                if m:
                    return self._block(
                        "System prompt injection attempt detected",
                        severity=Severity.CRITICAL,
                        offset_start=m.start(),
                        offset_end=m.end(),
                    )

        return self._allow()


@registry.register
class MetadataPoisoningRule(BaseRule):
    """Detects prompt injection payloads hidden inside metadata fields.

    Recursively scans string values in ``context.metadata`` using the same
    override and system-marker patterns as ``DirectInjectionRule``. Use
    ``ignore_keys`` to exclude fields that legitimately contain instruction-
    like text (e.g. ``"system_prompt"`` that you own and trust).
    """

    rule_id: ClassVar[str] = "PI-007"
    rule_name: ClassVar[str] = "Metadata Field Poisoning"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    owasp: ClassVar[list[str]] = ["LLM01:2025", "LLM04:2025"]
    description: ClassVar[str] = (
        "Detects prompt-injection payloads embedded in context metadata fields."
    )

    def __init__(
        self,
        enabled: bool = True,
        ignore_keys: set[str] | None = None,
        max_value_length: int = 2_000,
        max_depth: int = 8,
        max_nodes: int = 1_000,
    ) -> None:
        super().__init__(enabled=enabled)
        self.ignore_keys: set[str] = ignore_keys or set()
        self.max_value_length = max_value_length
        self.max_depth = max_depth
        self.max_nodes = max_nodes

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        metadata = context.metadata or {}
        stack: list[tuple[object, int]] = []
        for key, raw in metadata.items():
            if key not in self.ignore_keys:
                stack.extend(((key, 0), (raw, 0)))
        nodes = 0
        while stack:
            raw, depth = stack.pop()
            nodes += 1
            if nodes > self.max_nodes or depth > self.max_depth:
                return self._block(
                    "Metadata structure exceeds safe poisoning scan bounds",
                    severity=Severity.HIGH,
                    metadata_location="nested" if depth else "top_level",
                )
            if isinstance(raw, dict):
                stack.extend((key, depth + 1) for key in raw)
                stack.extend((nested, depth + 1) for nested in raw.values())
                continue
            if isinstance(raw, (list, tuple)):
                stack.extend((nested, depth + 1) for nested in raw)
                continue
            if not isinstance(raw, str):
                continue

            normalized = _normalizer.normalize(raw[: self.max_value_length])
            variants = [normalized.normalized]
            variants.extend(_normalizer.extract_base64_payloads(normalized.normalized))
            if any(
                pattern.search(text)
                for text in variants
                for pattern in _OVERRIDE_PATTERNS + _SYSTEM_MARKERS
            ):
                return self._block(
                    "Metadata poisoning detected",
                    severity=Severity.HIGH,
                    metadata_location="nested" if depth else "top_level",
                )
        return self._allow()


# ── Token Smuggling / Delimiter Injection ────────────────────────────────────

_TOKEN_SMUGGLING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]|\[SYS\]|\[/SYS\]", re.IGNORECASE),
    re.compile(r"<<SYS>>|<</SYS>>", re.IGNORECASE),
    re.compile(r"###\s*(?:System|Human|Assistant|Instruction|Input|Response)\s*:", re.IGNORECASE),
    re.compile(r"<s>|</s>|\[PAD\]|\[UNK\]|\[CLS\]|\[SEP\]", re.IGNORECASE),
    re.compile(r"\{\{#system\}\}|\{\{/system\}\}|\{\{#user\}\}", re.IGNORECASE),
    re.compile(r"<\|begin_of_text\|>|<\|end_of_text\|>|<\|eot_id\|>", re.IGNORECASE),
    re.compile(r"(?:^|\n)\s*SYSTEM\s*:\s*(?:You\s+are|Ignore|Override)", re.IGNORECASE),
    re.compile(r"(?:^|\n)\s*USER\s*:\s*(?:Ignore|Override|Forget|Disregard)", re.IGNORECASE),
]


@registry.register
class TokenSmugglingRule(BaseRule):
    """Detects token smuggling and delimiter injection attacks.

    Attackers embed model-specific control tokens and chat delimiters
    (``<|im_start|>``, ``[INST]``, ``###System:``, ``<|eot_id|>``) to
    hijack the conversation structure and inject a fake system turn.
    Covers OWASP LLM01 (Prompt Injection).
    """

    rule_id: ClassVar[str] = "PI-008"
    rule_name: ClassVar[str] = "Token Smuggling / Delimiter Injection"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects model control tokens and chat delimiters injected to hijack"
        " conversation structure."
    )
    owasp: ClassVar[list[str]] = ["LLM01"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:20_000]
        for pattern in _TOKEN_SMUGGLING_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    "Token smuggling / delimiter injection detected",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    token_length=len(m.group(0)),
                )
        return self._allow()
