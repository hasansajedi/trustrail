"""Tool call validation policy."""

from __future__ import annotations

from aiRail.policies.base import BasePolicy
from aiRail.rules.base import BaseRule
from aiRail.rules.tools import (
    DestructiveToolCallRule,
    IdorDetectionRule,
    PluginPermissionScopeRule,
    PrivilegeEscalationRule,
    ToolAllowlistRule,
    ToolArgumentRule,
)


class ToolPolicy(BasePolicy):
    """Policy for validating tool/function calls."""

    def __init__(
        self,
        enabled: bool = True,
        allowlist: list[str] | None = None,
        blocklist: list[str] | None = None,
        validate_args: bool = True,
        check_idor: bool = True,
        plugin_scopes: dict[str, set[str]] | None = None,
        check_destructive: bool = True,
        check_privilege_escalation: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.allowlist = allowlist
        self.blocklist = blocklist
        self.validate_args = validate_args
        self.check_idor = check_idor
        self.plugin_scopes = plugin_scopes
        self.check_destructive = check_destructive
        self.check_privilege_escalation = check_privilege_escalation

    def get_rules(self) -> list[BaseRule]:
        rules: list[BaseRule] = [
            ToolAllowlistRule(allowlist=self.allowlist, blocklist=self.blocklist),
        ]
        if self.validate_args:
            rules.append(ToolArgumentRule())
        if self.check_idor:
            rules.append(IdorDetectionRule())
        if self.plugin_scopes is not None:
            rules.append(PluginPermissionScopeRule(plugin_scopes=self.plugin_scopes))
        if self.check_destructive:
            rules.append(DestructiveToolCallRule())
        if self.check_privilege_escalation:
            rules.append(PrivilegeEscalationRule())
        return rules + self._rules
