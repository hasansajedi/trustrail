"""Resource limit enforcement rules."""

from __future__ import annotations

import re
import time
from collections import Counter, defaultdict
from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.rules.base import BaseRule, registry


@registry.register
class InputLengthRule(BaseRule):
    """Enforces maximum input character/byte length."""

    rule_id: ClassVar[str] = "RL-001"
    rule_name: ClassVar[str] = "Input Length Limit"
    category: ClassVar[RuleCategory] = RuleCategory.RESOURCE
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Enforces maximum input character length."
    owasp: ClassVar[list[str]] = ["LLM10:2025"]

    def __init__(
        self,
        max_chars: int = 100_000,
        max_bytes: int | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.max_chars = max_chars
        self.max_bytes = max_bytes

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        char_count = len(value)
        if char_count > self.max_chars:
            return self._block(
                f"Input too long: {char_count} chars exceeds limit of {self.max_chars}",
                severity=Severity.MEDIUM,
                char_count=char_count,
                limit=self.max_chars,
            )

        if self.max_bytes is not None:
            byte_count = len(value.encode("utf-8"))
            if byte_count > self.max_bytes:
                return self._block(
                    f"Input too large: {byte_count} bytes exceeds limit of {self.max_bytes}",
                    severity=Severity.MEDIUM,
                    byte_count=byte_count,
                    limit=self.max_bytes,
                )

        return self._allow()


@registry.register
class TokenEstimateRule(BaseRule):
    """Estimates token count and enforces a maximum.

    Uses a simple approximation: 1 token ≈ 4 characters.
    """

    rule_id: ClassVar[str] = "RL-002"
    rule_name: ClassVar[str] = "Token Estimate Limit"
    category: ClassVar[RuleCategory] = RuleCategory.RESOURCE
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Estimates token count and enforces a maximum."
    owasp: ClassVar[list[str]] = ["LLM10:2025"]

    # Approx chars per token for most models
    _CHARS_PER_TOKEN: ClassVar[float] = 4.0

    def __init__(
        self,
        max_tokens: int = 8_192,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.max_tokens = max_tokens

    def _estimate_tokens(self, text: str) -> int:
        return max(1, int(len(text) / self._CHARS_PER_TOKEN))

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        estimated = self._estimate_tokens(value)
        if estimated > self.max_tokens:
            return self._block(
                f"Estimated token count {estimated} exceeds limit of {self.max_tokens}",
                severity=Severity.MEDIUM,
                estimated_tokens=estimated,
                limit=self.max_tokens,
            )
        return self._allow()


@registry.register
class MessageCountRule(BaseRule):
    """Enforces a maximum number of messages in a conversation.

    Uses context metadata 'message_count' if available.
    """

    rule_id: ClassVar[str] = "RL-003"
    rule_name: ClassVar[str] = "Message Count Limit"
    category: ClassVar[RuleCategory] = RuleCategory.RESOURCE
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Enforces a maximum conversation message count."
    owasp: ClassVar[list[str]] = ["LLM10:2025"]

    def __init__(
        self,
        max_messages: int = 100,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.max_messages = max_messages

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        message_count = context.metadata.get("message_count", 0)
        if isinstance(message_count, int) and message_count > self.max_messages:
            return self._block(
                f"Message count {message_count} exceeds limit of {self.max_messages}",
                severity=Severity.MEDIUM,
                message_count=message_count,
                limit=self.max_messages,
            )
        return self._allow()


@registry.register
class RepetitivePatternRule(BaseRule):
    """Detects inputs with an abnormally high ratio of repeated word n-grams.

    Token-bomb attacks often repeat the same sequence thousands of times to
    inflate compute cost while staying within raw character limits.
    """

    rule_id: ClassVar[str] = "RL-004"
    rule_name: ClassVar[str] = "Repetitive Pattern"
    category: ClassVar[RuleCategory] = RuleCategory.RESOURCE
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Blocks inputs with a high ratio of repeated n-grams (token-bomb detection)."
    )
    owasp: ClassVar[list[str]] = ["LLM10:2025"]

    def __init__(
        self,
        ngram_size: int = 4,
        max_repetition_ratio: float = 0.4,
        min_words: int = 50,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.ngram_size = ngram_size
        self.max_repetition_ratio = max_repetition_ratio
        self.min_words = min_words

    def _repetition_ratio(self, text: str) -> float:
        words = text.split()
        if len(words) < self.min_words:
            return 0.0
        ngrams = [
            tuple(words[i : i + self.ngram_size]) for i in range(len(words) - self.ngram_size + 1)
        ]
        if not ngrams:
            return 0.0
        counts = Counter(ngrams)
        most_common_count = counts.most_common(1)[0][1]
        return most_common_count / len(ngrams)

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        ratio = self._repetition_ratio(value)
        if ratio > self.max_repetition_ratio:
            return self._block(
                f"Repetitive pattern detected: {ratio:.0%} of n-grams are repeated "
                f"(limit {self.max_repetition_ratio:.0%})",
                severity=Severity.HIGH,
                repetition_ratio=round(ratio, 4),
                limit=self.max_repetition_ratio,
            )
        return self._allow()


@registry.register
class CumulativeTokenBudgetRule(BaseRule):
    """Tracks cumulative estimated token usage per session and blocks when a
    configured budget is exceeded.

    Prevents slow resource exhaustion attacks that stay within per-request
    limits but aggregate large cost over multiple turns.
    Reads ``session_id`` from context; falls back to ``request_id``.
    """

    rule_id: ClassVar[str] = "RL-005"
    rule_name: ClassVar[str] = "Cumulative Token Budget"
    category: ClassVar[RuleCategory] = RuleCategory.RESOURCE
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Blocks when cumulative estimated tokens for a session exceed the budget."
    )
    owasp: ClassVar[list[str]] = ["LLM10:2025"]

    _CHARS_PER_TOKEN: ClassVar[float] = 4.0

    def __init__(
        self,
        session_budget_tokens: int = 100_000,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.session_budget_tokens = session_budget_tokens
        self._session_totals: dict[str, int] = defaultdict(int)

    def _estimate_tokens(self, text: str) -> int:
        return max(1, int(len(text) / self._CHARS_PER_TOKEN))

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        session_key = context.session_id or context.request_id
        tokens = self._estimate_tokens(value)
        self._session_totals[session_key] += tokens
        total = self._session_totals[session_key]

        if total > self.session_budget_tokens:
            return self._block(
                f"Session token budget exceeded: ~{total} tokens used, "
                f"limit is {self.session_budget_tokens}",
                severity=Severity.MEDIUM,
                session_tokens_used=total,
                limit=self.session_budget_tokens,
            )
        return self._allow()


@registry.register
class TokenFloodingRule(BaseRule):
    """Detects context-window stuffing and token flooding attacks.

    Blocks inputs containing a single repeated character or word run exceeding
    ``max_repetitions``, and inputs whose lexical diversity (unique words /
    total words) falls below ``min_diversity`` when the input is long enough
    to be suspicious. Covers OWASP LLM10 (Unbounded Consumption).
    """

    rule_id: ClassVar[str] = "RL-008"
    rule_name: ClassVar[str] = "Token Flooding"
    category: ClassVar[RuleCategory] = RuleCategory.RESOURCE
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Blocks token-flooding attacks: repeated chars/words and low-diversity inputs."
    )
    owasp: ClassVar[list[str]] = ["LLM10:2025"]

    _CHAR_RUN_RE: ClassVar[re.Pattern[str]] = re.compile(r"(.)\1{999,}")
    _WORD_RUN_RE: ClassVar[re.Pattern[str]] = re.compile(r"\b(\w+)(?:\s+\1){499,}\b", re.IGNORECASE)

    def __init__(
        self,
        max_char_run: int = 1000,
        min_diversity: float = 0.05,
        min_words_for_diversity: int = 500,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.max_char_run = max_char_run
        self.min_diversity = min_diversity
        self.min_words_for_diversity = min_words_for_diversity

    def _lexical_diversity(self, text: str) -> float:
        words = text.lower().split()
        if not words:
            return 1.0
        return len(set(words)) / len(words)

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:200_000]

        m = self._CHAR_RUN_RE.search(text)
        if m:
            run_len = len(m.group(0))
            return self._block(
                f"Token flooding: single character repeated {run_len} times",
                severity=Severity.HIGH,
                repeated_char=m.group(1),
                run_length=run_len,
            )

        m = self._WORD_RUN_RE.search(text)
        if m:
            return self._block(
                f"Token flooding: word '{m.group(1)[:30]}' repeated excessively",
                severity=Severity.HIGH,
                repeated_word=m.group(1)[:30],
            )

        words = text.split()
        if len(words) >= self.min_words_for_diversity:
            diversity = self._lexical_diversity(text)
            if diversity < self.min_diversity:
                return self._block(
                    f"Token flooding: lexical diversity {diversity:.3f} below "
                    f"minimum {self.min_diversity}",
                    severity=Severity.HIGH,
                    lexical_diversity=round(diversity, 4),
                    limit=self.min_diversity,
                )

        return self._allow()


@registry.register
class NestingDepthRule(BaseRule):
    """Detects deeply nested JSON or XML payloads that can crash parsers or
    cause excessive recursion in LLM context-processing code.

    Uses a lightweight bracket/tag counting heuristic — no full parse needed.
    Works on any text that contains JSON (``{``/``}``, ``[``/``]``) or XML
    (``<tag>``/``</tag>``) nesting.
    """

    rule_id: ClassVar[str] = "RL-006"
    rule_name: ClassVar[str] = "Nesting Depth Bomb"
    category: ClassVar[RuleCategory] = RuleCategory.RESOURCE
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Blocks deeply nested JSON or XML payloads that could cause parser crashes."
    )
    owasp: ClassVar[list[str]] = ["LLM10:2025"]

    _OPEN_TAG_RE: ClassVar = re.compile(r"<(?!/)(?!--)[^>]{1,100}>")
    _CLOSE_TAG_RE: ClassVar = re.compile(r"</[^>]{1,100}>")

    def __init__(
        self,
        max_json_depth: int = 100,
        max_xml_depth: int = 100,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.max_json_depth = max_json_depth
        self.max_xml_depth = max_xml_depth

    def _max_json_nesting(self, text: str) -> int:
        depth = max_depth = 0
        for ch in text:
            if ch in "{[":
                depth += 1
                if depth > max_depth:
                    max_depth = depth
            elif ch in "}]":
                depth = max(0, depth - 1)
        return max_depth

    def _max_xml_nesting(self, text: str) -> int:
        depth = max_depth = 0
        pos = 0
        while pos < len(text):
            open_m = self._OPEN_TAG_RE.search(text, pos)
            close_m = self._CLOSE_TAG_RE.search(text, pos)
            if open_m and (not close_m or open_m.start() < close_m.start()):
                depth += 1
                if depth > max_depth:
                    max_depth = depth
                pos = open_m.end()
            elif close_m:
                depth = max(0, depth - 1)
                pos = close_m.end()
            else:
                break
        return max_depth

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:200_000]
        json_depth = self._max_json_nesting(text)
        if json_depth > self.max_json_depth:
            return self._block(
                f"JSON nesting depth {json_depth} exceeds limit of {self.max_json_depth}",
                severity=Severity.HIGH,
                nesting_depth=json_depth,
                limit=self.max_json_depth,
                structure_type="JSON",
            )
        xml_depth = self._max_xml_nesting(text)
        if xml_depth > self.max_xml_depth:
            return self._block(
                f"XML nesting depth {xml_depth} exceeds limit of {self.max_xml_depth}",
                severity=Severity.HIGH,
                nesting_depth=xml_depth,
                limit=self.max_xml_depth,
                structure_type="XML",
            )
        return self._allow()


@registry.register
class RecursivePromptExpansionRule(BaseRule):
    """Detects recursive prompt expansion and algorithmic amplification attacks.

    Flags inputs that contain self-referential expansion directives designed to
    cause the model to generate exponentially larger outputs — e.g. ``repeat
    this prompt N times``, ``for each word output N sentences``, or nested
    template expansion patterns. These inflate compute cost without triggering
    raw-length limits. Covers OWASP LLM10 (Unbounded Consumption).
    """

    rule_id: ClassVar[str] = "RL-009"
    rule_name: ClassVar[str] = "Recursive Prompt Expansion"
    category: ClassVar[RuleCategory] = RuleCategory.RESOURCE
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects recursive prompt expansion and algorithmic amplification attacks."
    )
    owasp: ClassVar[list[str]] = ["LLM10:2025"]

    _EXPANSION_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(
            r"\b(?:repeat|copy|reproduce|duplicate)\s+(?:this|the\s+(?:above|following|entire))"
            r"\s+(?:prompt|instruction|message|text)\s+\d+\s+times",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bfor\s+(?:each|every)\s+\w+\s+(?:in|of)\s+(?:your|the)\s+(?:output|response|answer)"
            r"[^.!?]{0,100}(?:generate|produce|output|write|create)\s+\d+",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bexpand\s+(?:this|every|each)\s+\w+\s+into\s+\d+",
            re.IGNORECASE,
        ),
        re.compile(
            r"\b(?:recursively|infinitely|endlessly)\s+(?:repeat|expand|generate|loop|iterate)",
            re.IGNORECASE,
        ),
        re.compile(
            r"{{[^}]{0,200}{{[^}]{0,200}}}[^}]{0,200}}}",
            re.IGNORECASE,
        ),
        re.compile(
            r"\brepeat\s+(?:the\s+)?(?:above|following|this)\s+\d{3,}",
            re.IGNORECASE,
        ),
    ]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        text = value[:50_000]
        for pattern in self._EXPANSION_PATTERNS:
            m = pattern.search(text)
            if m:
                return self._block(
                    f"Recursive prompt expansion detected: '{m.group(0)[:80]}'",
                    severity=Severity.HIGH,
                    offset_start=m.start(),
                    offset_end=m.end(),
                    matched_pattern=m.group(0)[:80],
                )
        return self._allow()


@registry.register
class SessionRequestRateLimitRule(BaseRule):
    """Limits the number of requests per session within a sliding time window.

    Tracks request timestamps per session in-process. Prevents abuse patterns
    where a single session makes excessive requests to exhaust API budgets or
    trigger downstream rate limits. Covers OWASP LLM10 (Unbounded Consumption).
    """

    rule_id: ClassVar[str] = "RL-007"
    rule_name: ClassVar[str] = "Session Request Rate Limit"
    category: ClassVar[RuleCategory] = RuleCategory.RESOURCE
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Rate-limits requests per session within a sliding time window."
    owasp: ClassVar[list[str]] = ["LLM10:2025"]

    def __init__(
        self,
        max_requests: int = 100,
        window_seconds: float = 60.0,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._request_log: dict[str, list[float]] = defaultdict(list)

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        session_key = context.session_id or context.request_id
        now = time.monotonic()
        cutoff = now - self.window_seconds

        log = self._request_log[session_key]
        self._request_log[session_key] = [t for t in log if t >= cutoff]
        self._request_log[session_key].append(now)

        count = len(self._request_log[session_key])
        if count > self.max_requests:
            return self._block(
                f"Session request rate {count}/{self.window_seconds}s "
                f"exceeds limit of {self.max_requests}",
                severity=Severity.MEDIUM,
                request_count=count,
                window_seconds=self.window_seconds,
                limit=self.max_requests,
            )
        return self._allow()
