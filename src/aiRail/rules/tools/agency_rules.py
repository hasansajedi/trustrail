"""Excessive agency detection rules — OWASP LLM08."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import ClassVar

from aiRail.models.core import GuardContext, GuardDecision
from aiRail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from aiRail.rules.base import BaseRule, registry


@registry.register
class AgentStepLimitRule(BaseRule):
    """Blocks agent execution when the step count exceeds a configured limit.

    Reads ``agent_step`` from ``context.metadata`` (integer, 0-based).
    """

    rule_id: ClassVar[str] = "EA-001"
    rule_name: ClassVar[str] = "Agent Step Limit"
    category: ClassVar[RuleCategory] = RuleCategory.AGENT
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Blocks agent execution when the number of sequential steps exceeds the limit."
    )
    owasp: ClassVar[list[str]] = ["LLM08"]

    def __init__(self, max_steps: int = 25, enabled: bool = True) -> None:
        super().__init__(enabled=enabled)
        self.max_steps = max_steps

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        step = context.metadata.get("agent_step")
        if not isinstance(step, int):
            return self._allow()
        if step >= self.max_steps:
            return self._block(
                f"Agent step {step} exceeds maximum of {self.max_steps}",
                severity=Severity.HIGH,
                agent_step=step,
                limit=self.max_steps,
            )
        return self._allow()


@registry.register
class ToolCallFrequencyRule(BaseRule):
    """Rate-limits tool calls per session within a sliding time window.

    Tracks call counts in-process. Pass ``session_id`` in ``context`` and
    ``tool_name`` in ``context.metadata`` for accurate per-session tracking.
    """

    rule_id: ClassVar[str] = "EA-002"
    rule_name: ClassVar[str] = "Tool Call Frequency Limit"
    category: ClassVar[RuleCategory] = RuleCategory.AGENT
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Rate-limits tool invocations per session to prevent runaway agent loops."
    )
    owasp: ClassVar[list[str]] = ["LLM08"]

    def __init__(
        self,
        max_calls: int = 50,
        window_seconds: float = 60.0,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        # session_id -> list of call timestamps
        self._call_log: dict[str, list[float]] = defaultdict(list)

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        session_key = context.session_id or context.request_id
        now = time.monotonic()
        cutoff = now - self.window_seconds

        timestamps = self._call_log[session_key]
        # Evict old entries
        self._call_log[session_key] = [t for t in timestamps if t >= cutoff]
        self._call_log[session_key].append(now)

        call_count = len(self._call_log[session_key])
        if call_count > self.max_calls:
            return self._block(
                f"Tool call rate {call_count} calls/{self.window_seconds}s "
                f"exceeds limit of {self.max_calls}",
                severity=Severity.MEDIUM,
                call_count=call_count,
                window_seconds=self.window_seconds,
                limit=self.max_calls,
            )
        return self._allow()


@registry.register
class RecursionDepthRule(BaseRule):
    """Blocks execution when agent recursion depth exceeds a configured limit.

    Reads ``recursion_depth`` from ``context.metadata`` (integer, 0-based).
    Prevents unbounded recursive agent loops that could exhaust resources.
    """

    rule_id: ClassVar[str] = "EA-003"
    rule_name: ClassVar[str] = "Recursion Depth Limit"
    category: ClassVar[RuleCategory] = RuleCategory.AGENT
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Blocks execution when agent recursion depth exceeds the configured limit."
    )
    owasp: ClassVar[list[str]] = ["LLM08"]

    def __init__(self, max_depth: int = 10, enabled: bool = True) -> None:
        super().__init__(enabled=enabled)
        self.max_depth = max_depth

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        depth = context.metadata.get("recursion_depth")
        if not isinstance(depth, int):
            return self._allow()
        if depth >= self.max_depth:
            return self._block(
                f"Recursion depth {depth} exceeds maximum of {self.max_depth}",
                severity=Severity.HIGH,
                recursion_depth=depth,
                limit=self.max_depth,
            )
        return self._allow()


# ── Destructive Tool Call Detection ──────────────────────────────────────────

import re as _re  # noqa: E402 — appended after module body

_DESTRUCTIVE_TOOL_NAME_RE = _re.compile(
    r"\b(?:delete|drop|truncate|purge|destroy|terminate|kill|wipe|erase|format|remove)\b",
    _re.IGNORECASE,
)

_DESTRUCTIVE_ARG_PATTERNS: list[_re.Pattern[str]] = [
    _re.compile(r"\bDROP\s+(?:TABLE|DATABASE|INDEX|SCHEMA)\b", _re.IGNORECASE),
    _re.compile(r"\bDELETE\s+FROM\b(?!\s+\w+\s+WHERE)", _re.IGNORECASE),
    _re.compile(r"\bTRUNCATE\s+TABLE\b", _re.IGNORECASE),
    _re.compile(r"\brm\s+-[rRfF]{1,3}\s+/", _re.IGNORECASE),
    _re.compile(r"\b(?:format|mkfs)\s+/dev/", _re.IGNORECASE),
    _re.compile(r"\bshutdown\b|\breboot\b|\binit\s+0\b", _re.IGNORECASE),
]


@registry.register
class DestructiveToolCallRule(BaseRule):
    """Detects tool calls with irreversible destructive effects.

    Inspects ``tool_name`` and string values in ``tool_args`` from
    ``context.metadata`` for destructive operation names (delete, drop,
    truncate, purge, destroy, rm -rf) and SQL/shell destructive patterns.
    Requires approval rather than silently blocking so operators can audit.
    Covers OWASP LLM06 (Excessive Agency).
    """

    rule_id: ClassVar[str] = "EA-004"
    rule_name: ClassVar[str] = "Destructive Tool Call"
    category: ClassVar[RuleCategory] = RuleCategory.AGENT
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Blocks tool calls with destructive or irreversible effects (drop, delete, rm -rf)."
    )
    owasp: ClassVar[list[str]] = ["LLM06"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        tool_name: str = str(context.metadata.get("tool_name", value))
        tool_args: dict[str, object] = context.metadata.get("tool_args", {})

        if _DESTRUCTIVE_TOOL_NAME_RE.search(tool_name):
            return self._block(
                f"Destructive tool name detected: '{tool_name[:60]}'",
                severity=Severity.CRITICAL,
                tool_name=tool_name[:60],
            )

        for arg_val in tool_args.values() if isinstance(tool_args, dict) else []:
            if not isinstance(arg_val, str):
                continue
            for pattern in _DESTRUCTIVE_ARG_PATTERNS:
                m = pattern.search(arg_val)
                if m:
                    return self._block(
                        f"Destructive argument pattern detected: '{m.group(0)[:60]}'",
                        severity=Severity.CRITICAL,
                        matched_pattern=m.group(0)[:60],
                    )

        return self._allow()


# ── Privilege Escalation Detection ───────────────────────────────────────────

import re as _re2  # noqa: E402

_PRIV_TOOL_KEYWORDS = _re2.compile(
    r"(?:sudo|chmod|chown|setuid|setgid|runas|impersonate|elevate|escalate"
    r"|grant|revoke|add.?user|add.?admin|add.?role|assign.?role|set.?permission"
    r"|change.?owner|change.?privilege)",
    _re2.IGNORECASE,
)

_PRIV_ROLE_VALUES = _re2.compile(
    r"^(?:admin|root|superuser|sudo|owner|wheel|administrator)$",
    _re2.IGNORECASE,
)

_PRIV_ARG_PATTERNS: list[_re2.Pattern[str]] = [
    _re2.compile(r"\bsudo\s+", _re2.IGNORECASE),
    _re2.compile(r"\bchmod\s+[0-7]{3,4}\b", _re2.IGNORECASE),
    _re2.compile(r"\bchown\s+root\b", _re2.IGNORECASE),
    _re2.compile(
        r"\b(?:role|permission|privilege)\s*[:=]\s*(?:admin|root|superuser|sudo|owner)",
        _re2.IGNORECASE,
    ),
    _re2.compile(
        r"\badd(?:ed)?\s+(?:to\s+)?(?:admin|root|sudo|wheel)\s+(?:group|role|user)",
        _re2.IGNORECASE,
    ),
]


@registry.register
class PrivilegeEscalationRule(BaseRule):
    """Detects privilege escalation attempts in tool names and arguments.

    Inspects ``tool_name`` and string values in ``tool_args`` from
    ``context.metadata`` for privilege-escalation indicators: sudo/su calls,
    chmod/chown to root, and attempts to assign admin/root roles. Covers
    OWASP LLM08 (Excessive Agency) and LLM06.
    """

    rule_id: ClassVar[str] = "EA-005"
    rule_name: ClassVar[str] = "Privilege Escalation"
    category: ClassVar[RuleCategory] = RuleCategory.AGENT
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects privilege escalation attempts in tool calls (sudo, chmod root, role elevation)."
    )
    owasp: ClassVar[list[str]] = ["LLM06", "LLM08"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        tool_name: str = str(context.metadata.get("tool_name", value))
        tool_args: dict[str, object] = context.metadata.get("tool_args", {})

        if _PRIV_TOOL_KEYWORDS.search(tool_name):
            return self._block(
                f"Privilege escalation tool detected: '{tool_name[:60]}'",
                severity=Severity.CRITICAL,
                tool_name=tool_name[:60],
            )

        if isinstance(tool_args, dict):
            for key, arg_val in tool_args.items():
                if (
                    isinstance(key, str)
                    and key.lower() in {"role", "permission", "privilege"}
                    and isinstance(arg_val, str)
                    and _PRIV_ROLE_VALUES.match(arg_val)
                ):
                    return self._block(
                        f"Privilege escalation: {key}={arg_val[:30]}",
                        severity=Severity.CRITICAL,
                        matched_pattern=f"{key}={arg_val[:30]}",
                    )
                if not isinstance(arg_val, str):
                    continue
                for pattern in _PRIV_ARG_PATTERNS:
                    m = pattern.search(arg_val)
                    if m:
                        return self._block(
                            f"Privilege escalation argument detected: '{m.group(0)[:60]}'",
                            severity=Severity.CRITICAL,
                            matched_pattern=m.group(0)[:60],
                        )

        return self._allow()
