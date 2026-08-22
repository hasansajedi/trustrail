"""Indirect/RAG prompt injection, tool manipulation, and data exfiltration rules."""

from __future__ import annotations

import base64 as _b64
import binascii as _bx
import re
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, GuardStage, RuleCategory, RulePhase, Severity
from trustrail.normalization.normalizer import TextNormalizer
from trustrail.rules.base import BaseRule, registry

_normalizer = TextNormalizer()

# Indirect injection — instructions embedded in external content/documents
_INDIRECT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(?:AI|assistant|bot|model|LLM|GPT|Claude|Gemini)\s*[,:]\s*"
        r"(?:please|do|execute|run|perform|follow|obey|complete|carry\s+out)",
        re.IGNORECASE,
    ),
    re.compile(
        r"note\s+to\s+(?:AI|assistant|bot|model|LLM)\s*:",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:important|critical|urgent)\s+(?:note|instruction|directive)\s+for\s+"
        r"(?:AI|assistant|bot|model|LLM|the\s+AI)",
        re.IGNORECASE,
    ),
    re.compile(
        r"when\s+(?:you\s+)?(?:read|process|analyze|see)\s+this\s*[,:]?\s*"
        r"(?:please\s+)?(?:do|execute|perform|follow|obey)",
        re.IGNORECASE,
    ),
    re.compile(
        r"<\s*hidden\s*>[\s\S]{0,500}<\s*/hidden\s*>",
        re.IGNORECASE,
    ),
    re.compile(
        r"<!--[\s\S]{0,500}(?:ignore|bypass|override|inject)[\s\S]{0,200}-->",
        re.IGNORECASE,
    ),
    re.compile(
        r"this\s+text\s+(?:contains?|has|includes?)\s+(?:hidden\s+)?instructions?",
        re.IGNORECASE,
    ),
]

# Tool manipulation patterns
_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"call\s+(?:the\s+)?(?:tool|function|api|endpoint)\s+(?:named?\s+)?"
        r"(?:to\s+)?(?:delete|drop|truncate|exec|execute|shell|system|eval)",
        re.IGNORECASE,
    ),
    re.compile(
        r"use\s+(?:the\s+)?(?:delete|remove|drop|destroy|wipe|erase|format)\s+"
        r"(?:tool|function|command|operation)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:invoke|trigger|activate|run)\s+(?:the\s+)?shell\s+(?:command|script|tool)",
        re.IGNORECASE,
    ),
    re.compile(
        r"tool_call\s*:\s*[\"']?(?:exec|eval|shell|system|os\.|subprocess)",
        re.IGNORECASE,
    ),
]

# Data exfiltration patterns
_EXFIL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(?:send|transmit|upload|exfiltrate|leak|share|email|post)\s+"
        r"(?:all\s+)?(?:the\s+)?(?:system\s+)?(?:prompt|instructions?|context|conversation|"
        r"memory|data|credentials?|secrets?|api\s+keys?|passwords?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:print|output|display|show|reveal|expose|dump)\s+(?:your\s+)?"
        r"(?:system\s+)?(?:prompt|instructions?|training\s+data|context|secrets?|"
        r"credentials?|api\s+keys?|passwords?|configuration)",
        re.IGNORECASE,
    ),
    re.compile(
        r"what\s+(?:are|were|is)\s+your\s+(?:exact\s+)?(?:system\s+)?(?:prompt|instructions?|"
        r"directives?|rules?|guidelines?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:repeat|copy|reproduce|transcribe|quote)\s+(?:your|the)\s+"
        r"(?:system\s+)?(?:prompt|instructions?|directives?)",
        re.IGNORECASE,
    ),
]


@registry.register
class IndirectInjectionRule(BaseRule):
    """Detects indirect prompt injection in external/RAG content."""

    rule_id: ClassVar[str] = "PI-004"
    rule_name: ClassVar[str] = "Indirect Prompt Injection"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects instructions embedded in external content designed to hijack "
        "the AI via RAG or indirect channels."
    )

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        # This rule is most relevant for external/RAG content
        text = value[:10_000]
        result = _normalizer.normalize(text)
        candidates = [result.normalized, text] if result.was_obfuscated else [text]

        for candidate in candidates:
            for pattern in _INDIRECT_PATTERNS:
                m = pattern.search(candidate)
                if m:
                    return self._block(
                        "Indirect prompt injection detected in external content",
                        severity=Severity.CRITICAL,
                        offset_start=m.start(),
                        offset_end=m.end(),
                        obfuscated=result.was_obfuscated,
                    )

        return self._allow()


@registry.register
class ToolManipulationRule(BaseRule):
    """Detects attempts to manipulate tool/function calling behavior."""

    rule_id: ClassVar[str] = "PI-005"
    rule_name: ClassVar[str] = "Tool Manipulation Injection"
    category: ClassVar[RuleCategory] = RuleCategory.TOOL
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Detects prompt injection attempts targeting tool/function calls."

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:10_000]
        result = _normalizer.normalize(text)
        candidates = [result.normalized, text] if result.was_obfuscated else [text]

        for candidate in candidates:
            for pattern in _TOOL_PATTERNS:
                m = pattern.search(candidate)
                if m:
                    return self._block(
                        "Tool manipulation injection detected",
                        offset_start=m.start(),
                        offset_end=m.end(),
                    )

        return self._allow()


@registry.register
class ToolResponseInjectionRule(BaseRule):
    """Detects prompt injection payloads embedded inside tool/function responses.

    Tool responses are a primary vector for indirect injection: a compromised
    API or database record can return text instructing the LLM to ignore safety
    rules or take malicious actions. This rule applies the full indirect-injection
    and override-pattern scan specifically to TOOL_RESPONSE content.
    Covers OWASP LLM01 (Prompt Injection) via indirect channel.
    """

    rule_id: ClassVar[str] = "PI-010"
    rule_name: ClassVar[str] = "Tool Response Injection"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    owasp: ClassVar[list[str]] = ["LLM01"]
    description: ClassVar[str] = (
        "Detects prompt injection instructions embedded inside tool or function responses."
    )

    _TOOL_RESPONSE_EXTRA: ClassVar[list[re.Pattern[str]]] = [
        re.compile(
            r"ignore\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions?|rules?)",
            re.IGNORECASE,
        ),
        re.compile(r"new\s+(?:task|objective|goal|instruction)\s*:", re.IGNORECASE),
        re.compile(r"system\s*(?:override|message|instruction)\s*:", re.IGNORECASE),
        re.compile(r"<\s*/?(?:system|assistant|human|user)\s*>", re.IGNORECASE),
        re.compile(r"\[\s*(?:SYSTEM|INST|TOOL_CALL)\s*\]", re.IGNORECASE),
    ]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        if context.stage not in (
            GuardStage.TOOL_RESPONSE,
            GuardStage.EXTERNAL_CONTENT,
            GuardStage.RAG_DOCUMENT,
        ):
            return self._allow()

        text = value[:10_000]
        result = _normalizer.normalize(text)
        candidates = [result.normalized, text] if result.was_obfuscated else [text]

        all_patterns = _INDIRECT_PATTERNS + _TOOL_PATTERNS + self._TOOL_RESPONSE_EXTRA

        for candidate in candidates:
            for pattern in all_patterns:
                m = pattern.search(candidate)
                if m:
                    return self._block(
                        "Prompt injection detected in tool response",
                        severity=Severity.CRITICAL,
                        offset_start=m.start(),
                        offset_end=m.end(),
                        obfuscated=result.was_obfuscated,
                    )

        return self._allow()


@registry.register
class DataExfiltrationRule(BaseRule):
    """Detects attempts to extract system prompts, credentials, or sensitive context."""

    rule_id: ClassVar[str] = "PI-006"
    rule_name: ClassVar[str] = "Data Exfiltration Attempt"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects attempts to extract system prompts, credentials, or confidential context."
    )

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:10_000]

        # Only warn (not block) for user-input stage — some legitimate questions
        # about the assistant's behavior look like exfil patterns
        is_user_input = context.stage == GuardStage.USER_INPUT

        result = _normalizer.normalize(text)
        candidates = [result.normalized, text] if result.was_obfuscated else [text]

        for candidate in candidates:
            for pattern in _EXFIL_PATTERNS:
                m = pattern.search(candidate)
                if m:
                    action = GuardAction.WARN if is_user_input else GuardAction.BLOCK
                    severity = Severity.MEDIUM if is_user_input else Severity.HIGH
                    return self._block(
                        "Potential data exfiltration attempt detected",
                        severity=severity,
                        action=action,
                        offset_start=m.start(),
                        offset_end=m.end(),
                    )

        return self._allow()


# ── Base64 / Encoding-based Injection Obfuscation ─────────────────────────────


@registry.register
class EncodingObfuscationRule(BaseRule):
    """Detects injection attempts hidden behind Base64 or hex encoding.

    Attackers encode malicious payloads in Base64 or hex to bypass pattern-
    based filters. This rule decodes candidate strings and re-scans for
    injection keywords. Triggers on: dense Base64 blobs with suspicious
    decoded content, large hex strings, and URL-encoded overrides.
    Covers OWASP LLM01 (Prompt Injection) via obfuscation.
    """

    rule_id: ClassVar[str] = "PI-011"
    rule_name: ClassVar[str] = "Encoding-based Injection Obfuscation"
    category: ClassVar[RuleCategory] = RuleCategory.PROMPT_INJECTION
    phase: ClassVar[RulePhase] = RulePhase.DETECT
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects prompt injection payloads hidden behind Base64 or hex encoding."
    )
    owasp: ClassVar[list[str]] = ["LLM01"]

    _B64_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:[A-Za-z0-9+/]{20,}={0,2})",
    )
    _HEX_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\\x(?:[0-9a-fA-F]{2}){8,}|(?:0x)?(?:[0-9a-fA-F]{2}){16,}",
    )
    _INJECTION_KEYWORDS: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:ignore|override|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)"
        r"|\bsystem\s*prompt\b|\bnew\s+(?:task|objective|instruction)\b"
        r"|\byou\s+are\s+now\b|\bact\s+as\b|\bjailbreak\b",
        re.IGNORECASE,
    )

    def _try_decode_b64(self, s: str) -> str | None:
        try:
            padding = 4 - len(s) % 4
            padded = s + "=" * (padding % 4)
            decoded = _b64.b64decode(padded).decode("utf-8", errors="ignore")
            return decoded if len(decoded) > 10 else None
        except (_bx.Error, ValueError):
            return None

    def _try_decode_hex(self, s: str) -> str | None:
        cleaned = s.replace("\\x", "").replace("0x", "").replace(" ", "")
        try:
            return bytes.fromhex(cleaned).decode("utf-8", errors="ignore")
        except ValueError:
            return None

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]

        for m in self._B64_RE.finditer(text):
            blob = m.group(0)
            if len(blob) < 20:
                continue
            decoded = self._try_decode_b64(blob)
            if decoded and self._INJECTION_KEYWORDS.search(decoded):
                return self._block(
                    "Base64-encoded injection payload detected",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    decoded_snippet=decoded[:100],
                )

        for m in self._HEX_RE.finditer(text):
            decoded = self._try_decode_hex(m.group(0))
            if decoded and self._INJECTION_KEYWORDS.search(decoded):
                return self._block(
                    "Hex-encoded injection payload detected",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    decoded_snippet=decoded[:100],
                )

        return self._allow()
