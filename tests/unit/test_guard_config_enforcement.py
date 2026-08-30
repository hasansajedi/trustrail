"""Acceptance coverage for GuardConfig runtime enforcement."""

from __future__ import annotations

import time
from typing import ClassVar

import pytest

from trustrail import (
    ConfigurationError,
    FailMode,
    Guard,
    GuardAction,
    GuardConfig,
    GuardContext,
    GuardPolicy,
    GuardStage,
    MemoryAuditSink,
    RuleCategory,
    RuleConfig,
    Severity,
)
from trustrail.models.core import GuardDecision
from trustrail.rules.base import BaseRule


class ConfigurableTestRule(BaseRule):
    rule_id: ClassVar[str] = "TEST-CONFIG"
    rule_name: ClassVar[str] = "Configurable test rule"
    category: ClassVar[RuleCategory] = RuleCategory.CONTENT_SAFETY
    default_severity: ClassVar[Severity] = Severity.HIGH

    def __init__(self, marker: str = "trigger", enabled: bool = True) -> None:
        super().__init__(enabled=enabled)
        self.marker = marker

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        del context
        if self.marker in value:
            return self._block("Test marker found", confidence=0.6)
        return self._allow()


class SlowTestRule(BaseRule):
    rule_id: ClassVar[str] = "TEST-SLOW"
    rule_name: ClassVar[str] = "Slow test rule"
    category: ClassVar[RuleCategory] = RuleCategory.CONTENT_SAFETY

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        del value, context
        time.sleep(0.5)
        return self._allow()


def _quiet_config(**kwargs: object) -> GuardConfig:
    return GuardConfig(audit_enabled=False, **kwargs)  # type: ignore[arg-type]


def test_policy_enablement_defaults_and_params_are_enforced() -> None:
    disabled = Guard(
        _quiet_config(
            max_text_length=1,
            policies={"resource": GuardPolicy(enabled=False)},
        )
    )
    assert "RL-001" not in {
        finding.rule_id for finding in disabled.check("long", GuardStage.USER_INPUT).findings
    }

    configured = Guard(_quiet_config(policies={"resource": GuardPolicy(params={"max_chars": 3})}))
    result = configured.check("long", GuardStage.USER_INPUT)
    assert result.action == GuardAction.BLOCK
    assert any(finding.rule_id == "RL-001" for finding in result.findings)

    top_level_default = Guard(_quiet_config(max_text_length=3))
    assert any(
        finding.rule_id == "RL-001"
        for finding in top_level_default.check("long", GuardStage.USER_INPUT).findings
    )


def test_category_allowlist_then_denylist_precedence() -> None:
    allowlisted = Guard(
        _quiet_config(enabled_categories=[RuleCategory.CONTENT_SAFETY]),
        extra_rules=[ConfigurableTestRule()],
    )
    assert all(
        rule.category == RuleCategory.CONTENT_SAFETY
        for rule in allowlisted._get_rules_for_stage(GuardStage.USER_INPUT)
    )

    denied = Guard(
        _quiet_config(
            enabled_categories=[RuleCategory.CONTENT_SAFETY],
            disabled_categories=[RuleCategory.CONTENT_SAFETY],
        ),
        extra_rules=[ConfigurableTestRule()],
    )
    assert denied._get_rules_for_stage(GuardStage.USER_INPUT) == []


def test_policy_default_and_rule_override_precedence() -> None:
    policy_default = Guard(
        _quiet_config(
            policies={"resource": GuardPolicy(default_action=GuardAction.WARN)},
            max_text_length=1,
        )
    )
    assert policy_default.check("long", GuardStage.USER_INPUT).action == GuardAction.WARN

    policy_rule = Guard(
        _quiet_config(
            policies={
                "resource": GuardPolicy(
                    default_action=GuardAction.BLOCK,
                    rules={"RL-001": RuleConfig(action=GuardAction.WARN)},
                )
            },
            max_text_length=1,
        )
    )
    assert policy_rule.check("long", GuardStage.USER_INPUT).action == GuardAction.WARN

    guard = Guard(
        _quiet_config(
            policies={
                "resource": GuardPolicy(
                    default_action=GuardAction.BLOCK,
                    rules={"RL-001": RuleConfig(action=GuardAction.WARN)},
                )
            },
            rule_overrides={"RL-001": RuleConfig(action=GuardAction.ALLOW)},
            max_text_length=1,
        )
    )
    result = guard.check("long", GuardStage.USER_INPUT)

    assert any(finding.rule_id == "RL-001" for finding in result.findings)
    assert result.action == GuardAction.ALLOW


def test_every_per_rule_control_is_enforced() -> None:
    disabled = Guard(
        _quiet_config(
            rule_overrides={"TEST-CONFIG": RuleConfig(enabled=False)},
        ),
        extra_rules=[ConfigurableTestRule()],
    )
    assert not disabled.check("trigger", GuardStage.USER_INPUT).findings

    configured = Guard(
        _quiet_config(
            rule_overrides={
                "TEST-CONFIG": RuleConfig(
                    action=GuardAction.WARN,
                    severity_override=Severity.LOW,
                    threshold=0.5,
                    params={"marker": "configured"},
                )
            }
        ),
        extra_rules=[ConfigurableTestRule()],
    )
    assert not configured.check("trigger", GuardStage.USER_INPUT).findings
    result = configured.check("configured", GuardStage.USER_INPUT)
    assert result.action == GuardAction.WARN
    assert result.findings[0].severity == Severity.LOW

    filtered = Guard(
        _quiet_config(
            rule_overrides={"TEST-CONFIG": RuleConfig(threshold=0.7)},
        ),
        extra_rules=[ConfigurableTestRule()],
    )
    assert not filtered.check("trigger", GuardStage.USER_INPUT).findings


def test_rule_action_override_is_enforced_during_streaming() -> None:
    guard = Guard(
        _quiet_config(
            rule_overrides={
                "TEST-CONFIG": RuleConfig(action=GuardAction.QUARANTINE),
            }
        ),
        extra_rules=[ConfigurableTestRule()],
    )

    result = guard.stream(GuardStage.STREAM).process_chunk("trigger")
    assert result.action == GuardAction.QUARANTINE
    assert result.safe_chunk == ""
    assert result.is_terminal


def test_policy_fail_mode_overrides_global_failure_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = Guard(
        _quiet_config(
            fail_mode=FailMode.CLOSED,
            policies={"resource": GuardPolicy(fail_mode=FailMode.OPEN)},
        )
    )
    rule = next(rule for rule in guard._policy_rules["resource"] if rule.rule_id == "RL-001")

    def fail(value: str, context: GuardContext) -> GuardDecision:
        del value, context
        raise RuntimeError("expected failure")

    monkeypatch.setattr(rule, "evaluate", fail)
    result = guard.check("safe", GuardStage.USER_INPUT)
    assert not any(finding.rule_id == "RL-001" for finding in result.findings)
    assert result.is_allowed


@pytest.mark.parametrize(
    ("config", "message"),
    [
        (GuardConfig(policies={"missing": GuardPolicy()}), "Unknown policy ID"),
        (GuardConfig(rule_overrides={"MISSING": RuleConfig()}), "Unknown or inactive rule ID"),
        (
            GuardConfig(policies={"resource": GuardPolicy(params={"missing": True})}),
            "Unsupported parameter",
        ),
        (
            GuardConfig(rule_overrides={"RL-001": RuleConfig(params={"missing": True})}),
            "Unsupported parameter",
        ),
        (
            GuardConfig(policies={"resource": GuardPolicy(rules={"MISSING": RuleConfig()})}),
            "Unknown or inactive rule ID",
        ),
    ],
)
def test_invalid_configuration_fails_during_guard_construction(
    config: GuardConfig,
    message: str,
) -> None:
    with pytest.raises(ConfigurationError, match=message):
        Guard(config)


def test_stateful_rules_are_reused_across_checks() -> None:
    guard = Guard(
        _quiet_config(
            policies={
                "resource": GuardPolicy(
                    params={
                        "max_requests_per_session": 1,
                        "request_rate_window_seconds": 60,
                    }
                )
            }
        )
    )
    context = GuardContext(session_id="stable-session")

    assert guard.check("first", GuardStage.USER_INPUT, context=context).is_allowed
    second = guard.check("second", GuardStage.USER_INPUT, context=context)
    assert any(finding.rule_id == "RL-007" for finding in second.findings)


@pytest.mark.parametrize(
    ("fail_mode", "expected_action"),
    [(FailMode.CLOSED, GuardAction.BLOCK), (FailMode.OPEN, GuardAction.WARN)],
)
def test_sync_timeout_honors_fail_mode(
    fail_mode: FailMode,
    expected_action: GuardAction,
) -> None:
    guard = Guard(
        _quiet_config(timeout_seconds=0.1, fail_mode=fail_mode),
        extra_rules=[SlowTestRule()],
    )
    started_at = time.perf_counter()
    result = guard.check("safe", GuardStage.USER_INPUT)

    assert time.perf_counter() - started_at < 0.4
    assert result.action == expected_action
    assert result.findings[0].rule_id == "SYS-001"


@pytest.mark.asyncio
async def test_async_timeout_is_enforced() -> None:
    guard = Guard(
        _quiet_config(timeout_seconds=0.1),
        extra_rules=[SlowTestRule()],
    )
    started_at = time.perf_counter()
    result = await guard.acheck("safe", GuardStage.USER_INPUT)

    assert time.perf_counter() - started_at < 0.4
    assert result.action == GuardAction.BLOCK
    assert result.findings[0].rule_id == "SYS-001"


@pytest.mark.parametrize("include_metadata", [True, False])
def test_audit_include_metadata_controls_context_fields(include_metadata: bool) -> None:
    sink = MemoryAuditSink()
    guard = Guard(
        GuardConfig(audit_include_metadata=include_metadata),
        audit_sink=sink,
    )
    context = GuardContext(
        request_id="request",
        session_id="session",
        user_id="user",
        tenant_id="tenant",
        tags=["tag"],
    )

    guard.check("safe", GuardStage.USER_INPUT, context=context)
    event = sink.events[0]
    assert event.request_id == ("request" if include_metadata else None)
    assert event.session_id == ("session" if include_metadata else None)
    assert event.user_id == ("user" if include_metadata else None)
    assert event.tenant_id == ("tenant" if include_metadata else None)
    assert event.tags == (["tag"] if include_metadata else [])
