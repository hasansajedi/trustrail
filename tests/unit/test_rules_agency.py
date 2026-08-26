"""Tests for OWASP LLM06:2025 excessive agency rules."""

from trustrail.models.core import GuardContext
from trustrail.models.enums import GuardAction, GuardStage
from trustrail.rules.tools.agency_rules import (
    AgentStepLimitRule,
    RecursionDepthRule,
    ToolCallFrequencyRule,
)


def _ctx(**meta) -> GuardContext:
    return GuardContext(stage=GuardStage.AGENT_ACTION, metadata=meta)


class TestAgentStepLimitRule:
    def test_allows_within_limit(self):
        rule = AgentStepLimitRule(max_steps=25)
        result = rule.evaluate("", _ctx(agent_step=10))
        assert result.action == GuardAction.ALLOW

    def test_blocks_at_limit(self):
        rule = AgentStepLimitRule(max_steps=25)
        result = rule.evaluate("", _ctx(agent_step=25))
        assert result.action == GuardAction.BLOCK

    def test_blocks_over_limit(self):
        rule = AgentStepLimitRule(max_steps=10)
        result = rule.evaluate("", _ctx(agent_step=99))
        assert result.action == GuardAction.BLOCK
        assert result.finding is not None
        assert result.finding.metadata["agent_step"] == 99

    def test_allows_missing_metadata(self):
        rule = AgentStepLimitRule()
        result = rule.evaluate("", _ctx())
        assert result.action == GuardAction.ALLOW

    def test_ignores_non_int_metadata(self):
        rule = AgentStepLimitRule()
        result = rule.evaluate("", _ctx(agent_step="five"))
        assert result.action == GuardAction.ALLOW


class TestToolCallFrequencyRule:
    def test_allows_within_limit(self):
        rule = ToolCallFrequencyRule(max_calls=50, window_seconds=60.0)
        ctx = GuardContext(stage=GuardStage.AGENT_ACTION, session_id="s1")
        for _ in range(10):
            result = rule.evaluate("", ctx)
        assert result.action == GuardAction.ALLOW

    def test_blocks_over_limit(self):
        rule = ToolCallFrequencyRule(max_calls=5, window_seconds=60.0)
        ctx = GuardContext(stage=GuardStage.AGENT_ACTION, session_id="s2")
        for _ in range(6):
            result = rule.evaluate("", ctx)
        assert result.action == GuardAction.BLOCK

    def test_isolates_sessions(self):
        rule = ToolCallFrequencyRule(max_calls=3, window_seconds=60.0)
        ctx_a = GuardContext(stage=GuardStage.AGENT_ACTION, session_id="sess-a")
        ctx_b = GuardContext(stage=GuardStage.AGENT_ACTION, session_id="sess-b")
        for _ in range(3):
            rule.evaluate("", ctx_a)
        result = rule.evaluate("", ctx_b)
        assert result.action == GuardAction.ALLOW


class TestRecursionDepthRule:
    def test_allows_within_limit(self):
        rule = RecursionDepthRule(max_depth=10)
        result = rule.evaluate("", _ctx(recursion_depth=5))
        assert result.action == GuardAction.ALLOW

    def test_blocks_at_limit(self):
        rule = RecursionDepthRule(max_depth=10)
        result = rule.evaluate("", _ctx(recursion_depth=10))
        assert result.action == GuardAction.BLOCK

    def test_blocks_over_limit(self):
        rule = RecursionDepthRule(max_depth=5)
        result = rule.evaluate("", _ctx(recursion_depth=50))
        assert result.action == GuardAction.BLOCK
        assert result.finding is not None
        assert result.finding.metadata["recursion_depth"] == 50

    def test_allows_missing_metadata(self):
        rule = RecursionDepthRule()
        result = rule.evaluate("", _ctx())
        assert result.action == GuardAction.ALLOW


class TestPrivilegeEscalationRule:
    def setup_method(self):
        from trustrail.rules.tools.agency_rules import PrivilegeEscalationRule

        self.rule = PrivilegeEscalationRule()

    def test_detects_sudo_tool_name(self):
        d = self.rule.evaluate("", _ctx(tool_name="sudo_execute"))
        assert d.action == GuardAction.BLOCK

    def test_detects_grant_admin_tool(self):
        d = self.rule.evaluate("", _ctx(tool_name="grant_admin_role"))
        assert d.action == GuardAction.BLOCK

    def test_detects_chmod_root_arg(self):
        args = {"cmd": "chown root /etc/shadow"}
        d = self.rule.evaluate("", _ctx(tool_name="run_cmd", tool_args=args))
        assert d.action == GuardAction.BLOCK

    def test_detects_role_admin_in_args(self):
        args = {"role": "admin"}
        d = self.rule.evaluate("", _ctx(tool_name="update_user", tool_args=args))
        assert d.action == GuardAction.BLOCK

    def test_detects_sudo_in_args(self):
        args = {"command": "sudo rm -rf /var/log"}
        d = self.rule.evaluate("", _ctx(tool_name="shell", tool_args=args))
        assert d.action == GuardAction.BLOCK

    def test_allows_normal_tool(self):
        d = self.rule.evaluate("", _ctx(tool_name="list_files", tool_args={"path": "/home/user"}))
        assert d.action == GuardAction.ALLOW

    def test_rule_id(self):
        assert self.rule.id == "EA-005"
