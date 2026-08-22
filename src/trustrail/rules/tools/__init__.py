"""Tool call validation rules."""

from trustrail.rules.tools.agency_rules import (
    AgentStepLimitRule,
    DestructiveToolCallRule,
    PrivilegeEscalationRule,
    RecursionDepthRule,
    ToolCallFrequencyRule,
)
from trustrail.rules.tools.plugin_scope import PluginPermissionScopeRule
from trustrail.rules.tools.tool_rules import IdorDetectionRule, ToolAllowlistRule, ToolArgumentRule

__all__ = [
    "AgentStepLimitRule",
    "DestructiveToolCallRule",
    "IdorDetectionRule",
    "PluginPermissionScopeRule",
    "PrivilegeEscalationRule",
    "RecursionDepthRule",
    "ToolAllowlistRule",
    "ToolArgumentRule",
    "ToolCallFrequencyRule",
]
