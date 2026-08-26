"""Plugin permission scope enforcement — OWASP LLM06:2025."""

from __future__ import annotations

from typing import ClassVar

from trustrail.models.core import GuardContext, GuardDecision, ToolCall
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.rules.base import BaseRule, registry


@registry.register
class PluginPermissionScopeRule(BaseRule):
    """Validates that a plugin tool call falls within its declared permission scope.

    Each plugin should declare the set of operations it is permitted to perform
    (its ``scope``). This rule blocks any tool call whose name is not in the
    plugin's declared scope, preventing privilege escalation and out-of-scope
    actions (OWASP LLM06:2025).

    Usage::

        rule = PluginPermissionScopeRule(
            plugin_scopes={
                "calendar_plugin": {"read_events", "create_event"},
                "email_plugin": {"send_email", "read_inbox"},
            }
        )

    The ``plugin_name`` and ``tool_name`` are read from ``context.metadata``.
    If ``plugin_name`` is not in the declared scopes, the call is allowed
    (the rule only enforces plugins it knows about).
    """

    rule_id: ClassVar[str] = "TL-003"
    rule_name: ClassVar[str] = "Plugin Permission Scope"
    category: ClassVar[RuleCategory] = RuleCategory.TOOL
    phase: ClassVar[RulePhase] = RulePhase.VALIDATE
    default_severity: ClassVar[Severity] = Severity.HIGH
    default_action: ClassVar[GuardAction] = GuardAction.BLOCK
    description: ClassVar[str] = (
        "Validates plugin tool calls against declared permission scopes to prevent "
        "privilege escalation."
    )
    owasp: ClassVar[list[str]] = ["LLM06:2025"]

    def __init__(
        self,
        plugin_scopes: dict[str, set[str]] | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.plugin_scopes: dict[str, set[str]] = plugin_scopes or {}

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        plugin_name = context.metadata.get("plugin_name")
        tool_name = context.metadata.get("tool_name", value.strip())

        if not plugin_name or plugin_name not in self.plugin_scopes:
            return self._allow()

        allowed_operations = self.plugin_scopes[plugin_name]
        if tool_name not in allowed_operations:
            return self._block(
                f"Plugin '{plugin_name}' is not permitted to call '{tool_name}'. "
                f"Allowed operations: {sorted(allowed_operations)}",
                severity=Severity.HIGH,
                plugin_name=plugin_name,
                tool_name=tool_name,
                allowed_operations=sorted(allowed_operations),
            )
        return self._allow()

    def validate_tool_call(
        self,
        tool_call: ToolCall,
        context: GuardContext,
        plugin_name: str,
    ) -> GuardDecision:
        """Validate a ToolCall directly with an explicit plugin name."""
        ctx_copy = GuardContext(
            **context.model_dump(exclude={"metadata"}),
            metadata={
                **context.metadata,
                "plugin_name": plugin_name,
                "tool_name": tool_call.name,
            },
        )
        return self.evaluate(tool_call.name, ctx_copy)
