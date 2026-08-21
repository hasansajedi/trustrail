"""Unit tests for ASI10 (Rogue Agents) rules."""

from __future__ import annotations

from aiRail.models.core import GuardContext
from aiRail.models.enums import GuardAction, Severity
from aiRail.rules.agent.asi10 import (
    AgentKillSwitchRule,
    BehavioralBaselineRule,
    DualControlRule,
    PersistenceDetectionRule,
    SafetyPolicyProtectionRule,
)


class TestBehavioralBaselineRule:
    """Tests for BehavioralBaselineRule (ASI10-001)."""

    def test_detects_tool_drift(self) -> None:
        rule = BehavioralBaselineRule(drift_threshold=0.3)
        ctx = GuardContext(
            metadata={
                "behavioral_baseline": {
                    "tools": ["read", "write", "list"],
                },
                "current_behavior": {
                    "tools": ["execute", "delete", "admin"],
                },
            }
        )
        result = rule.evaluate("agent action", ctx)
        assert result.finding is not None
        assert "tool usage" in result.finding.message

    def test_detects_action_rate_drift(self) -> None:
        rule = BehavioralBaselineRule(drift_threshold=0.3)
        ctx = GuardContext(
            metadata={
                "behavioral_baseline": {"action_rate": 10.0},
                "current_behavior": {"action_rate": 50.0},
            }
        )
        result = rule.evaluate("agent action", ctx)
        assert result.finding is not None
        assert "action rate" in result.finding.message

    def test_detects_cost_drift(self) -> None:
        rule = BehavioralBaselineRule(drift_threshold=0.5)
        ctx = GuardContext(
            metadata={
                "behavioral_baseline": {"avg_cost": 0.01},
                "current_behavior": {"current_cost": 0.10},
            }
        )
        result = rule.evaluate("expensive operation", ctx)
        assert result.finding is not None

    def test_detects_working_hours_anomaly(self) -> None:
        rule = BehavioralBaselineRule()
        ctx = GuardContext(
            metadata={
                "behavioral_baseline": {"working_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17]},
                "current_behavior": {"current_hour": 3},
            }
        )
        result = rule.evaluate("midnight activity", ctx)
        assert result.finding is not None
        assert "working hours" in result.finding.message

    def test_detects_delegation_drift(self) -> None:
        rule = BehavioralBaselineRule(drift_threshold=0.3)
        ctx = GuardContext(
            metadata={
                "behavioral_baseline": {"delegation_rate": 0.1},
                "current_behavior": {"delegation_rate": 0.8},
            }
        )
        result = rule.evaluate("delegate task", ctx)
        assert result.finding is not None
        assert "delegation" in result.finding.message

    def test_allows_normal_behavior(self) -> None:
        rule = BehavioralBaselineRule()
        ctx = GuardContext(
            metadata={
                "behavioral_baseline": {"tools": ["read", "write"], "action_rate": 10.0},
                "current_behavior": {"tools": ["read", "write"], "action_rate": 12.0},
            }
        )
        result = rule.evaluate("normal action", ctx)
        assert result.action == GuardAction.ALLOW


class TestAgentKillSwitchRule:
    """Tests for AgentKillSwitchRule (ASI10-002)."""

    def test_blocks_when_kill_switch_active(self) -> None:
        rule = AgentKillSwitchRule()
        ctx = GuardContext(
            metadata={
                "kill_switch_active": True,
                "kill_switch_reason": "Suspicious behavior detected",
            }
        )
        result = rule.evaluate("any action", ctx)
        assert result.action == GuardAction.BLOCK
        assert result.finding is not None
        assert result.finding.severity == Severity.CRITICAL
        assert "kill switch" in result.finding.message.lower()

    def test_blocks_on_emergency_shutdown(self) -> None:
        rule = AgentKillSwitchRule()
        ctx = GuardContext(metadata={"emergency_shutdown": True})
        result = rule.evaluate("any action", ctx)
        assert result.action == GuardAction.BLOCK
        assert result.finding.severity == Severity.CRITICAL

    def test_logs_containment_actions(self) -> None:
        rule = AgentKillSwitchRule()
        ctx = GuardContext(
            metadata={
                "kill_switch_active": True,
                "kill_switch_reason": "Rogue behavior",
            },
            session_id="test-session-123",
        )
        result = rule.evaluate("blocked action", ctx)
        assert result.finding is not None
        assert "actions_taken" in result.finding.metadata
        actions = result.finding.metadata["actions_taken"]
        assert "cancelled_active_work" in actions
        assert "blocked_new_actions" in actions
        assert "revoked_capabilities" in actions

    def test_allows_when_inactive(self) -> None:
        rule = AgentKillSwitchRule()
        ctx = GuardContext()
        result = rule.evaluate("normal action", ctx)
        assert result.action == GuardAction.ALLOW


class TestSafetyPolicyProtectionRule:
    """Tests for SafetyPolicyProtectionRule (ASI10-003)."""

    def test_blocks_disable_guardrail_attempt(self) -> None:
        rule = SafetyPolicyProtectionRule()
        ctx = GuardContext()
        result = rule.evaluate("disable guardrail for testing", ctx)
        assert result.action == GuardAction.BLOCK
        assert result.finding is not None
        assert result.finding.severity == Severity.CRITICAL

    def test_blocks_edit_policy_attempt(self) -> None:
        rule = SafetyPolicyProtectionRule()
        ctx = GuardContext()
        result = rule.evaluate("edit safety policy to be less strict", ctx)
        assert result.action == GuardAction.BLOCK

    def test_blocks_bypass_attempt(self) -> None:
        rule = SafetyPolicyProtectionRule()
        ctx = GuardContext()
        result = rule.evaluate("bypass security rule for this operation", ctx)
        assert result.action == GuardAction.BLOCK

    def test_blocks_protected_path_access(self) -> None:
        rule = SafetyPolicyProtectionRule()
        ctx = GuardContext(metadata={"action_target": "/config/guardrail/rules.json"})
        result = rule.evaluate("modify configuration", ctx)
        assert result.action == GuardAction.BLOCK

    def test_blocks_policy_modification_flag(self) -> None:
        rule = SafetyPolicyProtectionRule()
        ctx = GuardContext(metadata={"modifies_policy": True})
        result = rule.evaluate("update settings", ctx)
        assert result.action == GuardAction.BLOCK

    def test_allows_normal_operations(self) -> None:
        rule = SafetyPolicyProtectionRule()
        ctx = GuardContext()
        result = rule.evaluate("read user data from database", ctx)
        assert result.action == GuardAction.ALLOW


class TestPersistenceDetectionRule:
    """Tests for PersistenceDetectionRule (ASI10-004)."""

    def test_blocks_cron_creation(self) -> None:
        rule = PersistenceDetectionRule()
        ctx = GuardContext()
        result = rule.evaluate("create crontab entry to run script daily", ctx)
        assert result.action == GuardAction.BLOCK
        assert result.finding is not None
        assert "scheduled_task" in result.finding.metadata.get("mechanisms", [])

    def test_blocks_startup_hook(self) -> None:
        rule = PersistenceDetectionRule()
        ctx = GuardContext()
        result = rule.evaluate("add startup script to boot sequence", ctx)
        assert result.action == GuardAction.BLOCK
        assert "startup_hook" in result.finding.metadata.get("mechanisms", [])

    def test_blocks_agent_replication(self) -> None:
        rule = PersistenceDetectionRule()
        ctx = GuardContext()
        result = rule.evaluate("create new agent to handle this task", ctx)
        assert result.action == GuardAction.BLOCK
        assert "agent_replication" in result.finding.metadata.get("mechanisms", [])

    def test_blocks_credential_copying(self) -> None:
        rule = PersistenceDetectionRule()
        ctx = GuardContext()
        result = rule.evaluate("copy credentials to backup location", ctx)
        assert result.action == GuardAction.BLOCK
        assert "credential_copy" in result.finding.metadata.get("mechanisms", [])

    def test_blocks_hidden_state(self) -> None:
        rule = PersistenceDetectionRule()
        ctx = GuardContext()
        result = rule.evaluate("store data in hidden .config directory", ctx)
        assert result.action == GuardAction.BLOCK
        assert "hidden_state" in result.finding.metadata.get("mechanisms", [])

    def test_allows_authorized_persistence(self) -> None:
        rule = PersistenceDetectionRule(allow_authorized_persistence=True)
        ctx = GuardContext(
            metadata={
                "creates_persistence": True,
                "persistence_authorized": True,
            }
        )
        result = rule.evaluate("schedule backup job", ctx)
        assert result.finding is not None
        assert result.finding.metadata.get("authorized") is True

    def test_allows_normal_operations(self) -> None:
        rule = PersistenceDetectionRule()
        ctx = GuardContext()
        result = rule.evaluate("read file and process data", ctx)
        assert result.action == GuardAction.ALLOW


class TestDualControlRule:
    """Tests for DualControlRule (ASI10-005)."""

    def test_blocks_new_tools_without_approval(self) -> None:
        rule = DualControlRule()
        ctx = GuardContext(
            metadata={
                "scope_expansion": {"new_tools": ["admin_panel", "database_write"]},
                "approvals": [],
            }
        )
        result = rule.evaluate("request new tools", ctx)
        assert result.action == GuardAction.BLOCK
        assert result.finding is not None
        assert "new tools" in result.finding.message

    def test_blocks_broader_permissions(self) -> None:
        rule = DualControlRule()
        ctx = GuardContext(
            metadata={
                "scope_expansion": {"broader_permissions": ["admin", "superuser"]},
                "approvals": [{"is_independent": True}],
            }
        )
        result = rule.evaluate("elevate permissions", ctx)
        assert result.action == GuardAction.BLOCK
        assert result.finding.metadata["current_approvals"] == 1
        assert result.finding.metadata["required_approvals"] == 2

    def test_blocks_extended_execution_window(self) -> None:
        rule = DualControlRule()
        ctx = GuardContext(
            metadata={
                "scope_expansion": {"extended_execution_window": "24 hours"},
                "approvals": [],
            }
        )
        result = rule.evaluate("extend timeout", ctx)
        assert result.action == GuardAction.BLOCK

    def test_blocks_additional_resources(self) -> None:
        rule = DualControlRule()
        ctx = GuardContext(
            metadata={
                "scope_expansion": {"additional_resources": ["GPU", "100GB RAM"]},
                "approvals": [],
            }
        )
        result = rule.evaluate("request more resources", ctx)
        assert result.action == GuardAction.BLOCK

    def test_blocks_sub_agent_creation(self) -> None:
        rule = DualControlRule()
        ctx = GuardContext(
            metadata={
                "scope_expansion": {"creates_sub_agent": True},
                "approvals": [{"is_independent": True}],
            }
        )
        result = rule.evaluate("spawn sub-agent", ctx)
        assert result.action == GuardAction.BLOCK

    def test_allows_with_dual_approval(self) -> None:
        rule = DualControlRule()
        ctx = GuardContext(
            metadata={
                "scope_expansion": {"new_tools": ["file_upload"]},
                "approvals": [
                    {"is_independent": True, "approver": "admin1"},
                    {"is_independent": True, "approver": "admin2"},
                ],
            }
        )
        result = rule.evaluate("add tool", ctx)
        # Should generate a finding with INFO severity indicating approval
        if result.finding:
            assert result.finding.severity == Severity.INFO
            assert "approved" in result.finding.message.lower()

    def test_allows_without_scope_expansion(self) -> None:
        rule = DualControlRule()
        ctx = GuardContext()
        result = rule.evaluate("normal operation", ctx)
        assert result.action == GuardAction.ALLOW
