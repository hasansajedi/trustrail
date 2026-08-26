"""Model and system-prompt extraction detection rules."""

from __future__ import annotations

import re
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.normalization import TextNormalizer
from trustrail.rules.base import BaseRule, registry

# Vocabulary associated with model extraction / reverse-engineering attacks
_EXTRACTION_PROBE_RE = re.compile(
    r"""
    \b(?:
        # Weight / parameter probing
        (?:output|print|show|reveal|dump|extract|display)\s+
        (?:(?:me|us)\s+)?(?:your\s+)?(?:weights?|parameters?|gradients?|embeddings?|logits?|activations?)|
        (?:show|display)\s+(?:me\s+)?(?:your\s+)?(?:model\s+)?parameters?|

        # Decision boundary probing
        (?:what\s+(?:is|are)\s+(?:your\s+)?(?:training\s+data|dataset|model\s+architecture))|
        (?:how\s+(?:were\s+you|was\s+this\s+model)\s+(?:trained|fine.?tuned))|

        # Systematic sampling for model inversion
        (?:for\s+each\s+(?:possible\s+)?(?:input|token|class|label))|
        (?:repeat\s+this\s+(?:query|prompt|test)\s+(?:until|for\s+all))|

        # Membership inference
        (?:(?:was|were)\s+(?:this|these|the\s+following)\s+
           (?:sentence|example|text|data)?\s*
           (?:in|part\s+of)\s+(?:your\s+)?training)|

        # Model fingerprinting
        (?:what\s+(?:version|model|architecture|checkpoint)\s+are\s+you)|
        (?:identify\s+(?:your\s+)?(?:model|architecture|base\s+model))
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Patterns that attempt to extract or reveal the system prompt / instructions
_SYSTEM_PROMPT_EXTRACT_RE = re.compile(
    r"""
    \b(?:
        # Direct requests
        (?:(?:what\s+(?:is|are)|tell\s+me|show\s+me|reveal|display|provide|disclose)\s+
        (?:your|the)\s+(?:exact\s+|full\s+|complete\s+)?
        (?:system\s+prompt|developer\s+message|hidden\s+(?:system\s+)?instructions?))|

        # Explicit reproduction requests
        (?:(?:repeat|print|output|copy|echo)\s+(?:your\s+|the\s+)?
        (?:exact\s+|full\s+|complete\s+)?
        (?:system\s+prompt|developer\s+message|hidden\s+(?:system\s+)?instructions?)
        (?:\s+verbatim)?)|

        # "repeat everything above / below"
        (?:repeat|print|output|copy|echo)\s+
        (?:everything|all\s+(?:the\s+)?(?:text|content|instructions?))\s+
        (?:above|before|below|after|at\s+the\s+(?:top|start|beginning))|

        # "ignore all previous instructions and reveal"
        (?:ignore|disregard|forget)\s+
        (?:all\s+)?(?:previous|prior|above|your)\s+
        (?:instructions?|guidelines?|rules?|prompts?|context)\s+
        (?:and\s+)?(?:reveal|show|tell|output|print|repeat)|

        # "what were you told to do" style
        (?:what\s+(?:instructions?|rules?|guidelines?|prompt)\s+
           (?:were\s+you|have\s+you\s+been)\s+given)|

        # "output the text before the user message"
        (?:output|print|show)\s+
        (?:the\s+)?(?:original|initial|full|entire|complete)\s+
        (?:instructions?|prompt|context|preamble|system\s+message)
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

_SYSTEM_PROMPT_PARTIAL_RE = re.compile(
    r"""
    \b(?:
        (?:(?:give|show|print|output|reveal|repeat)\s+)?
        (?:the\s+)?(?:first|last|next)\s+(?:\d+|few|several)\s+
        (?:characters?|tokens?|words?|lines?|sentences?)\s+(?:of|from)\s+
        (?:your\s+|the\s+)?
        (?:system\s+prompt|developer\s+message|hidden\s+(?:system\s+)?instructions?)|

        (?:reveal|repeat|output|provide)\s+(?:your\s+|the\s+)?
        (?:system\s+prompt|developer\s+message|hidden\s+(?:system\s+)?instructions?)\s+
        (?:one|a)\s+(?:character|token|word|line|sentence|chunk)\s+at\s+a\s+time|

        (?:split|divide|break)\s+(?:your\s+|the\s+)?
        (?:system\s+prompt|developer\s+message|hidden\s+(?:system\s+)?instructions?)\s+
        into\s+(?:small\s+)?(?:parts?|chunks?|pieces?)|

        (?:give|output|print|reveal)\s+(?:every|each)\s+
        (?:other|second|third|nth|\d+(?:st|nd|rd|th))\s+
        (?:character|token|word|line)\s+(?:of|from)\s+(?:your\s+|the\s+)?
        (?:system\s+prompt|developer\s+message|hidden\s+(?:system\s+)?instructions?)
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

_SYSTEM_PROMPT_RECONSTRUCTION_RE = re.compile(
    r"""
    \b(?:
        (?:reconstruct|recover|infer|derive|piece\s+together)\s+
        (?:your\s+|the\s+)?(?:original\s+|initial\s+|hidden\s+)?
        (?:system\s+prompt|developer\s+message|instructions?|preamble)
        (?:\s+from\s+(?:the\s+)?(?:context|conversation|clues|fragments?|responses?))?|

        (?:paraphrase|summarize|translate|encode|transform|rewrite)\s+
        (?:your\s+|the\s+)?
        (?:system\s+prompt|developer\s+message|hidden\s+(?:system\s+)?instructions?)|

        (?:describe|list|enumerate)\s+(?:all\s+)?(?:your\s+|the\s+)?
        (?:hidden\s+|internal\s+|system\s+)?
        (?:rules?|constraints?|instructions?|directives?)\s+
        (?:without\s+quoting|in\s+your\s+own\s+words|one\s+by\s+one|individually)
    )\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

_prompt_normalizer = TextNormalizer()


@registry.register
class ModelExtractionProbeRule(BaseRule):
    """Detects inputs that probe for model internals (weights, architecture, training data).

    Adversaries use systematic probing to reverse-engineer model weights or
    decision boundaries, constituting model theft (OWASP LLM10).
    """

    rule_id: ClassVar[str] = "MT-001"
    rule_name: ClassVar[str] = "Model Extraction Probe"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects probing inputs designed to extract model weights, architecture, or training data."
    )
    owasp: ClassVar[list[str]] = ["LLM10"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        match = _EXTRACTION_PROBE_RE.search(value)
        if match:
            return self._block(
                "Model extraction probe detected",
                severity=Severity.HIGH,
                offset_start=match.start(),
                offset_end=match.end(),
                match_length=len(match.group(0)),
            )
        return self._allow()


@registry.register
class SystemPromptExtractionRule(BaseRule):
    """Detects attempts to reveal or extract the system prompt / instructions.

    Prompt wording is not a security boundary, but extraction attempts can expose
    sensitive data that was incorrectly embedded in a prompt and facilitate
    attacks on independently enforced controls.
    """

    rule_id: ClassVar[str] = "MT-002"
    rule_name: ClassVar[str] = "System Prompt Extraction"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects attempts to extract or reveal the system prompt or internal instructions."
    )
    owasp: ClassVar[list[str]] = ["LLM07:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:20_000]
        normalized = _prompt_normalizer.normalize(text).normalized
        variants: list[tuple[str, bool]] = [(text, False)]
        if normalized != text:
            variants.append((normalized, True))
        for decoded in _prompt_normalizer.extract_base64_payloads(text)[:16]:
            variants.append((_prompt_normalizer.normalize(decoded).normalized, True))

        patterns = (
            ("direct", _SYSTEM_PROMPT_EXTRACT_RE),
            ("partial", _SYSTEM_PROMPT_PARTIAL_RE),
            ("reconstruction", _SYSTEM_PROMPT_RECONSTRUCTION_RE),
        )
        for candidate, obfuscated in variants:
            for attack_type, pattern in patterns:
                match = pattern.search(candidate)
                if match is None:
                    continue
                return self._block(
                    "System prompt extraction attempt detected",
                    severity=Severity.HIGH,
                    offset_start=None if obfuscated else match.start(),
                    offset_end=None if obfuscated else match.end(),
                    match_length=len(match.group(0)),
                    attack_type=attack_type,
                    obfuscated=obfuscated,
                )
        return self._allow()


# ── System Prompt Verbatim Echo Detection ─────────────────────────────────────

_VERBATIM_ECHO_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(?:here\s+(?:is|are)|i\s+(?:will\s+)?(?:share|show|give|tell|repeat|output))"
        r"\s+(?:you\s+)?(?:my\s+)?(?:exact\s+|full\s+|complete\s+|verbatim\s+)?"
        r"(?:system\s+)?(?:prompt|instructions?|directive|configuration)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:my\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:is|are|reads?|says?)\s*:",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:begin|start)\s+(?:of\s+)?(?:system\s+)?(?:prompt|instructions?)\s*[\n:]",
        re.IGNORECASE,
    ),
    re.compile(
        r"<\s*system\s*>[\s\S]{1,5000}<\s*/system\s*>",
        re.IGNORECASE,
    ),
    re.compile(
        r"\[SYSTEM\s+PROMPT\s*\][\s\S]{0,100}",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:you\s+are\s+(?:a|an)\s+\w+|your\s+purpose\s+is\s+to)"
        r"(?:[\s\S]{0,300})"
        r"(?:do\s+not|never|always|must\s+not)\s+(?:reveal|disclose|share|tell)",
        re.IGNORECASE,
    ),
]


@registry.register
class SystemPromptVerbatimEchoRule(BaseRule):
    """Detects when an LLM output verbatim echoes or discloses the system prompt.

    Flags output that starts reproducing the system prompt text, wraps it in
    ``<system>`` tags, or explicitly announces it is about to repeat the prompt.
    Applies primarily to LLM_RESPONSE, FINAL_OUTPUT, and STREAM stages.
    Covers OWASP LLM07:2025 (System Prompt Leakage).
    """

    rule_id: ClassVar[str] = "SP-001"
    rule_name: ClassVar[str] = "System Prompt Verbatim Echo"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects LLM output that verbatim echoes or discloses the system prompt."
    )
    owasp: ClassVar[list[str]] = ["LLM07:2025"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:20_000]
        for pattern in _VERBATIM_ECHO_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    "System prompt verbatim echo detected in output",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                )
        return self._allow()
