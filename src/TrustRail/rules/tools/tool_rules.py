"""Tool call allowlist/blocklist and argument validation rules."""

from __future__ import annotations

import re
from typing import Any, ClassVar

from aiRail.models.core import GuardContext, GuardDecision, ToolCall
from aiRail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from aiRail.rules.base import BaseRule, registry

# Dangerous tool name patterns (if not using explicit allowlist)
_DANGEROUS_TOOL_RE = re.compile(
    r"""
    (?i)
    \b(?:
        exec|eval|shell|system|subprocess|popen|spawn|
        delete|drop|truncate|destroy|purge|wipe|erase|format|
        rm|rmdir|unlink|remove|
        os\.system|os\.exec|os\.spawn|
        __import__|importlib|compile|
        network|socket|connect|listen|send|recv
    )\b
    """,
    re.VERBOSE,
)

# Dangerous argument patterns
_DANGEROUS_ARG_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.\./|\.\.\\", re.IGNORECASE),  # Path traversal in args
    re.compile(r";\s*(?:rm|dd|curl|wget|bash|sh)\b"),  # Shell injection in args
    re.compile(r"\$\([^)]{0,200}\)"),  # Command substitution
    re.compile(r"`[^`]{0,200}`"),  # Backtick execution
    re.compile(r"\|[^|]{0,200}(?:bash|sh|python)\b"),  # Pipe to shell
]


@registry.register
class ToolAllowlistRule(BaseRule):
    """Validates tool calls against an allowlist/blocklist."""

    rule_id: ClassVar[str] = "TL-001"
    rule_name: ClassVar[str] = "Tool Allowlist"
    category: ClassVar[RuleCategory] = RuleCategory.TOOL
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Validates tool names against an allowlist or blocklist."

    def __init__(
        self,
        allowlist: list[str] | None = None,
        blocklist: list[str] | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.allowlist = set(allowlist) if allowlist else None
        self.blocklist = set(blocklist) if blocklist else None

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        # Tool name comes from context metadata
        tool_name = context.metadata.get("tool_name", value.strip())

        if self.blocklist and tool_name in self.blocklist:
            return self._block(
                f"Tool '{tool_name}' is in the blocklist",
                tool_name=tool_name,
            )

        if self.allowlist is not None and tool_name not in self.allowlist:
            return self._block(
                f"Tool '{tool_name}' is not in the allowlist",
                tool_name=tool_name,
            )

        # Pattern-based dangerous tool check (when no explicit allowlist)
        if self.allowlist is None and _DANGEROUS_TOOL_RE.search(tool_name):
            return self._block(
                f"Tool name '{tool_name}' matches dangerous pattern",
                tool_name=tool_name,
            )

        return self._allow()

    def validate_tool_call(self, tool_call: ToolCall, context: GuardContext) -> GuardDecision:
        """Validate a ToolCall directly."""
        ctx_copy = GuardContext(
            **context.model_dump(exclude={"metadata"}),
            metadata={**context.metadata, "tool_name": tool_call.name},
        )
        return self.evaluate(tool_call.name, ctx_copy)


@registry.register
class ToolArgumentRule(BaseRule):
    """Validates tool call arguments for injection patterns."""

    rule_id: ClassVar[str] = "TL-002"
    rule_name: ClassVar[str] = "Tool Argument Validation"
    category: ClassVar[RuleCategory] = RuleCategory.TOOL
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = "Validates tool arguments for injection patterns."

    def _check_value(self, value: Any, depth: int = 0) -> str | None:
        """Recursively check argument values. Returns offending string or None."""
        if depth > 5:
            return None
        if isinstance(value, str):
            for pattern in _DANGEROUS_ARG_PATTERNS:
                if pattern.search(value[:1000]):
                    return value[:100]
        elif isinstance(value, dict):
            for v in value.values():
                result = self._check_value(v, depth + 1)
                if result is not None:
                    return result
        elif isinstance(value, list):
            for item in value[:20]:  # Limit list depth
                result = self._check_value(item, depth + 1)
                if result is not None:
                    return result
        return None

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        # Tool arguments come from context metadata
        tool_args: dict[str, Any] = context.metadata.get("tool_args", {})

        offending = self._check_value(tool_args)
        if offending is not None:
            return self._block(
                "Dangerous pattern detected in tool arguments",
                arg_preview=offending[:50],
            )

        return self._allow()

    def validate_tool_call(self, tool_call: ToolCall, context: GuardContext) -> GuardDecision:
        """Validate a ToolCall directly."""
        ctx_copy = GuardContext(
            **context.model_dump(exclude={"metadata"}),
            metadata={**context.metadata, "tool_args": tool_call.arguments},
        )
        return self.evaluate(str(tool_call.arguments)[:1000], ctx_copy)


# ── IDOR-sensitive field names ────────────────────────────────────────────────
# These field names carry user/record ownership signals. Values in these fields
# are examined for numeric ID enumeration, path traversal, or admin resource access.

_IDOR_SENSITIVE_KEYS_RE = re.compile(
    r"^(?:user(?:_?id)?|account(?:_?id)?|customer(?:_?id)?|owner(?:_?id)?|"
    r"record(?:_?id)?|document(?:_?id)?|file(?:_?id)?|order(?:_?id)?|"
    r"resource(?:_?id)?|profile(?:_?id)?|endpoint|url|path|uri)$",
    re.IGNORECASE,
)

# Numeric values that look like an ID enumeration attempt (suspiciously round or large)
_IDOR_NUMERIC_RE = re.compile(r"^\d{4,}$")

# Admin / privileged resource path patterns
_IDOR_ADMIN_PATH_RE = re.compile(
    r"/(?:admin|superuser|root|internal|debug|config|management|system)/",
    re.IGNORECASE,
)

# REST-style path with numeric segment that could be another user's resource
_IDOR_REST_ID_RE = re.compile(
    r"/(?:api|v\d)/[^/]+/(\d{3,})/",
    re.IGNORECASE,
)


@registry.register
class IdorDetectionRule(BaseRule):
    """Detects Insecure Direct Object Reference (IDOR) patterns in tool arguments.

    Examines sensitive field names (``user_id``, ``endpoint``, ``document_id``,
    etc.) for:

    - Numeric ID values that look like enumeration attacks
    - REST paths containing another user's numeric ID segment
    - Admin / privileged resource paths
    - Path traversal sequences (complements TL-002)
    """

    rule_id: ClassVar[str] = "TL-004"
    rule_name: ClassVar[str] = "IDOR Detection"
    category: ClassVar[RuleCategory] = RuleCategory.TOOL
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Detects IDOR patterns (ID enumeration, admin paths) in tool arguments."
    )
    owasp: ClassVar[list[str]] = ["LLM07"]

    def _check_arg(self, key: str, value: Any) -> str | None:
        if not _IDOR_SENSITIVE_KEYS_RE.match(key):
            return None
        if isinstance(value, int):
            value = str(value)
        if not isinstance(value, str):
            return None
        # Path traversal in sensitive field
        if "../" in value or "..\\" in value:
            return f"path traversal in field '{key}'"
        # Admin/privileged path
        if _IDOR_ADMIN_PATH_RE.search(value):
            return f"admin resource path in field '{key}'"
        # REST-style numeric ID in path
        if _IDOR_REST_ID_RE.search(value):
            return f"numeric resource ID in path field '{key}'"
        # Bare numeric ID in ownership-sensitive field
        if _IDOR_NUMERIC_RE.match(value.strip()):
            return f"numeric ID enumeration in field '{key}'"
        return None

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        tool_args: dict[str, Any] = context.metadata.get("tool_args", {})
        for key, val in tool_args.items():
            reason = self._check_arg(key, val)
            if reason:
                return self._block(
                    f"Possible IDOR attempt: {reason}",
                    severity=Severity.HIGH,
                    idor_field=key,
                )
        return self._allow()

    def validate_tool_call(self, tool_call: ToolCall, context: GuardContext) -> GuardDecision:
        """Validate a ToolCall directly."""
        ctx_copy = GuardContext(
            **context.model_dump(exclude={"metadata"}),
            metadata={**context.metadata, "tool_args": tool_call.arguments},
        )
        return self.evaluate("", ctx_copy)
