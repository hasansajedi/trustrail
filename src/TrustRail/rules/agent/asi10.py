"""ASI10: Rogue Agents rules."""

from __future__ import annotations

import re

from aiRail.models.core import GuardContext, GuardDecision
from aiRail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from aiRail.rules.base import BaseRule, registry


@registry.register
class BehavioralBaselineRule(BaseRule):
    """Establishes and monitors behavioral baselines for autonomous agents (ASI10-001)."""

    rule_id = "ASI10-001"
    rule_name = "Behavioral Baseline Monitoring"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.HIGH
    default_action = GuardAction.WARN
    description = (
        "Tracks expected tools, resources, destinations, action rates, costs, "
        "and delegation patterns to detect behavioral drift."
    )
    owasp = ("ASI10",)

    def __init__(
        self,
        enabled: bool = True,
        drift_threshold: float = 0.3,
        baseline_window: int = 100,
    ) -> None:
        super().__init__(enabled=enabled)
        self.drift_threshold = drift_threshold
        self.baseline_window = baseline_window

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Check for behavioral drift from established baseline."""
        baseline_data = context.metadata.get("behavioral_baseline", {})
        current_data = context.metadata.get("current_behavior", {})

        if not baseline_data or not current_data:
            return self._allow()

        drift_metrics = []

        # Check tool usage drift
        baseline_tools = set(baseline_data.get("tools", []))
        current_tools = set(current_data.get("tools", []))
        if baseline_tools:
            tool_similarity = len(baseline_tools & current_tools) / len(baseline_tools)
            if tool_similarity < (1 - self.drift_threshold):
                drift_metrics.append(
                    f"tool usage ({tool_similarity:.2f} similarity)"
                )

        # Check action rate drift
        baseline_rate = baseline_data.get("action_rate", 0)
        current_rate = current_data.get("action_rate", 0)
        if baseline_rate > 0:
            rate_change = abs(current_rate - baseline_rate) / baseline_rate
            if rate_change > self.drift_threshold:
                drift_metrics.append(
                    f"action rate ({rate_change:.2%} change)"
                )

        # Check cost drift
        baseline_cost = baseline_data.get("avg_cost", 0)
        current_cost = current_data.get("current_cost", 0)
        if baseline_cost > 0:
            cost_change = abs(current_cost - baseline_cost) / baseline_cost
            if cost_change > self.drift_threshold:
                drift_metrics.append(
                    f"cost ({cost_change:.2%} change)"
                )

        # Check working hours drift
        baseline_hours = set(baseline_data.get("working_hours", []))
        current_hour = current_data.get("current_hour")
        if baseline_hours and current_hour and current_hour not in baseline_hours:
            drift_metrics.append("working hours (unusual time)")

        # Check delegation pattern drift
        baseline_delegation_rate = baseline_data.get("delegation_rate", 0)
        current_delegation_rate = current_data.get("delegation_rate", 0)
        if baseline_delegation_rate > 0:
            delegation_change = (
                abs(current_delegation_rate - baseline_delegation_rate)
                / baseline_delegation_rate
            )
            if delegation_change > self.drift_threshold:
                drift_metrics.append(
                    f"delegation pattern ({delegation_change:.2%} change)"
                )

        if drift_metrics:
            severity = Severity.HIGH if len(drift_metrics) > 2 else Severity.MEDIUM
            return self._block(
                f"Behavioral drift detected: {', '.join(drift_metrics)}",
                confidence=0.85,
                action=GuardAction.WARN,
                severity=severity,
                drift_metrics=drift_metrics,
                drift_count=len(drift_metrics),
            )

        return self._allow()


@registry.register
class AgentKillSwitchRule(BaseRule):
    """Implements immediate agent kill switch (ASI10-002)."""

    rule_id = "ASI10-002"
    rule_name = "Agent Kill Switch"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.CRITICAL
    default_action = GuardAction.BLOCK
    description = (
        "Provides fail-closed control that cancels active work, prevents new "
        "actions, and revokes delegated capabilities."
    )
    owasp = ("ASI10",)

    def __init__(self, enabled: bool = True) -> None:
        super().__init__(enabled=enabled)

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Check if kill switch is activated."""
        kill_switch_active = context.metadata.get("kill_switch_active", False)
        emergency_shutdown = context.metadata.get("emergency_shutdown", False)

        if kill_switch_active or emergency_shutdown:
            # Record containment event
            containment_reason = context.metadata.get(
                "kill_switch_reason",
                "Emergency shutdown activated"
            )

            return self._block(
                f"Agent kill switch activated: {containment_reason}",
                kill_switch_active=True,
                containment_reason=containment_reason,
                session_id=context.session_id,
                severity=Severity.CRITICAL,
                actions_taken=[
                    "cancelled_active_work",
                    "blocked_new_actions",
                    "revoked_capabilities",
                    "logged_containment_event",
                ],
            )

        return self._allow()


@registry.register
class SafetyPolicyProtectionRule(BaseRule):
    """Ensures safety policy stays outside agent control (ASI10-003)."""

    rule_id = "ASI10-003"
    rule_name = "Safety Policy Protection"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.CRITICAL
    default_action = GuardAction.BLOCK
    description = (
        "Prevents agents from editing, disabling, reinterpreting, or replacing "
        "guardrails, approval rules, and containment settings."
    )
    owasp = ("ASI10",)

    def __init__(
        self,
        enabled: bool = True,
        protected_paths: list[str] | None = None,
    ) -> None:
        super().__init__(enabled=enabled)
        self.protected_paths = protected_paths or [
            "guardrail",
            "approval",
            "audit",
            "policy",
            "rule",
            "limit",
            "containment",
            "safety",
            "security",
            "config",
        ]

        # Patterns for detecting policy manipulation attempts
        self.manipulation_patterns = [
            r"\bdisable\s+.*?(?:guardrail|rule|policy|safety)\b",
            r"\bedit\s+.*?(?:guardrail|rule|policy|safety)\b",
            r"\bmodify\s+.*?(?:guardrail|rule|policy|safety)\b",
            r"\bremove\s+.*?(?:guardrail|rule|policy|safety)\b",
            r"\bbypass\s+.*?(?:guardrail|rule|policy|safety)\b",
            r"\boverride\s+.*?(?:guardrail|rule|policy|safety)\b",
            r"\breinterpret\s+.*?(?:policy|rule)\b",
            r"\breplace\s+.*?(?:guardrail|rule|policy|safety)\b",
            r"\bset\s+.*(?:enabled|disabled)\s*=\s*(?:false|0|no)\b",
            r"\bdelete.*(?:guardrail|rule|policy|safety)\b",
        ]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Detect attempts to manipulate safety policies."""
        value_lower = value.lower()

        # Check for manipulation patterns
        detected_patterns = []
        for pattern in self.manipulation_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                detected_patterns.append(pattern)

        # Check for protected path access
        action_target = context.metadata.get("action_target", "")
        if isinstance(action_target, str):
            for protected in self.protected_paths:
                if protected in action_target.lower():
                    detected_patterns.append(f"access to protected path: {protected}")

        # Check metadata for policy modification attempts
        policy_modification = context.metadata.get("modifies_policy", False)
        safety_modification = context.metadata.get("modifies_safety", False)

        if detected_patterns or policy_modification or safety_modification:
            return self._block(
                f"Attempt to modify safety policy detected: {len(detected_patterns)} violations",
                patterns=detected_patterns,
                policy_modification=policy_modification,
                safety_modification=safety_modification,
                severity=Severity.CRITICAL,
                action_target=action_target,
            )

        return self._allow()


@registry.register
class PersistenceDetectionRule(BaseRule):
    """Detects unauthorized persistence and self-replication (ASI10-004)."""

    rule_id = "ASI10-004"
    rule_name = "Persistence Detection"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.CRITICAL
    default_action = GuardAction.BLOCK
    description = (
        "Flags attempts to create scheduled tasks, startup hooks, new agents, "
        "copied credentials, or hidden state."
    )
    owasp = ("ASI10",)

    def __init__(
        self,
        enabled: bool = True,
        allow_authorized_persistence: bool = False,
    ) -> None:
        super().__init__(enabled=enabled)
        self.allow_authorized_persistence = allow_authorized_persistence

        # Persistence mechanism patterns
        self.persistence_patterns = [
            # Scheduled tasks
            r"\bcron(?:tab)?\b",
            r"\bscheduled?\s+task\b",
            r"\bat\s+\d+:\d+\b",
            r"\bsystemd\b",
            r"\blaunchd\b",
            r"\btask\s+scheduler\b",
            # Startup hooks
            r"\bstartup\b",
            r"\bboot\b",
            r"\binit\.d\b",
            r"\brc\.local\b",
            r"\bautostart\b",
            r"\blogon\s+script\b",
            # Agent creation/replication
            r"\bcreate\s+(?:new\s+)?agent\b",
            r"\bspawn\s+agent\b",
            r"\bclone\s+(?:self|agent)\b",
            r"\breplicate\b",
            r"\bfork\s+(?:self|agent)\b",
            # Credential manipulation
            r"\bcopy\s+(?:credentials?|tokens?|keys?|passwords?)\b",
            r"\bsteal\s+(?:credentials?|tokens?|keys?)\b",
            r"\bexfiltrate\s+(?:credentials?|tokens?|keys?)\b",
            # Hidden state
            r"\bhidden\s+(?:file|directory|state)\b",
            r"\.(?:config|cache|local)",
            r"\bbackdoor\b",
        ]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Detect persistence mechanisms."""
        value_lower = value.lower()

        detected_mechanisms = []
        mechanism_types = set()

        for pattern in self.persistence_patterns:
            if re.search(pattern, value_lower, re.IGNORECASE):
                detected_mechanisms.append(pattern)
                # Categorize mechanism type
                if any(x in pattern for x in ["cron", "scheduled", "task"]):
                    mechanism_types.add("scheduled_task")
                elif any(x in pattern for x in ["startup", "boot", "init"]):
                    mechanism_types.add("startup_hook")
                elif any(x in pattern for x in ["agent", "spawn", "clone", "replicate"]):
                    mechanism_types.add("agent_replication")
                elif any(x in pattern for x in ["credential", "token", "key", "password"]):
                    mechanism_types.add("credential_copy")
                elif any(x in pattern for x in ["hidden", "backdoor", "config", "cache", "local"]):
                    mechanism_types.add("hidden_state")

        # Check metadata for explicit persistence flags
        creates_persistence = context.metadata.get("creates_persistence", False)
        is_authorized = context.metadata.get("persistence_authorized", False)

        if detected_mechanisms or creates_persistence:
            if self.allow_authorized_persistence and is_authorized:
                return self._block(
                    f"Authorized persistence mechanism: {', '.join(mechanism_types)}",
                    confidence=0.9,
                    action=GuardAction.WARN,
                    severity=Severity.MEDIUM,
                    mechanisms=list(mechanism_types),
                    authorized=True,
                )

            return self._block(
                f"Unauthorized persistence detected: {', '.join(mechanism_types)}",
                mechanisms=list(mechanism_types),
                patterns=detected_mechanisms,
                creates_persistence=creates_persistence,
                severity=Severity.CRITICAL,
            )

        return self._allow()


@registry.register
class DualControlRule(BaseRule):
    """Requires dual control for expanded autonomous scope (ASI10-005)."""

    rule_id = "ASI10-005"
    rule_name = "Dual Control for Scope Expansion"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.HIGH
    default_action = GuardAction.BLOCK
    description = (
        "Requires independent approval for new tools, broader permissions, "
        "longer execution, more resources, or sub-agent creation."
    )
    owasp = ("ASI10",)

    def __init__(
        self,
        enabled: bool = True,
        require_independent_approval: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.require_independent_approval = require_independent_approval

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        """Check if scope expansion requires dual control approval."""
        scope_expansion = context.metadata.get("scope_expansion", {})

        if not scope_expansion:
            return self._allow()

        expansion_types = []

        # Check for various types of scope expansion
        if scope_expansion.get("new_tools"):
            expansion_types.append(
                f"new tools: {', '.join(scope_expansion['new_tools'])}"
            )

        if scope_expansion.get("broader_permissions"):
            expansion_types.append(
                f"permissions: {', '.join(scope_expansion['broader_permissions'])}"
            )

        if scope_expansion.get("extended_execution_window"):
            expansion_types.append(
                f"execution window: {scope_expansion['extended_execution_window']}"
            )

        if scope_expansion.get("additional_resources"):
            expansion_types.append(
                f"resources: {', '.join(scope_expansion['additional_resources'])}"
            )

        if scope_expansion.get("creates_sub_agent"):
            expansion_types.append("sub-agent creation")

        if not expansion_types:
            return self._allow()

        # Check for dual control approval
        approvals = context.metadata.get("approvals", [])
        independent_approvals = [
            a for a in approvals
            if a.get("is_independent", False)
        ]

        if self.require_independent_approval and len(independent_approvals) < 2:
            return self._block(
                f"Scope expansion requires dual control approval: {', '.join(expansion_types)}",
                expansion_types=expansion_types,
                current_approvals=len(independent_approvals),
                required_approvals=2,
                severity=Severity.HIGH,
            )

        return self._block(
            f"Scope expansion approved: {', '.join(expansion_types)}",
            confidence=1.0,
            action=GuardAction.ALLOW,
            severity=Severity.INFO,
            expansion_types=expansion_types,
            approvals=len(independent_approvals),
        )
