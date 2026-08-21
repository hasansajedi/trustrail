"""Tool call validation rules."""

from aiRail.rules.tools.agency_rules import (
    AgentStepLimitRule,
    DestructiveToolCallRule,
    PrivilegeEscalationRule,
    RecursionDepthRule,
    ToolCallFrequencyRule,
)
from aiRail.rules.tools.plugin_scope import PluginPermissionScopeRule
from aiRail.rules.tools.tool_rules import IdorDetectionRule, ToolAllowlistRule, ToolArgumentRule

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
