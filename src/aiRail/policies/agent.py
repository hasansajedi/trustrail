"""Agent policy — tracks and enforces agent-level limits."""

from __future__ import annotations

from aiRail.models.core import GuardContext, GuardDecision
from aiRail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from aiRail.policies.base import BasePolicy
from aiRail.rules.agent.asi09 import (
    ConfirmationPromptRule,
    ContentOriginMarkingRule,
    DecisionEscalationRule,
    EvidenceRequirementRule,
    ManipulativeLanguageRule,
)
from aiRail.rules.agent.asi10 import (
    AgentKillSwitchRule,
    BehavioralBaselineRule,
    DualControlRule,
    PersistenceDetectionRule,
    SafetyPolicyProtectionRule,
)
from aiRail.rules.base import BaseRule, registry


@registry.register
class AgentStepLimitRule(BaseRule):
    """Enforces a maximum number of agent steps per session."""

    rule_id = "AG-001"
    rule_name = "Agent Step Limit"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.HIGH
    default_action = GuardAction.BLOCK
    description = "Enforces maximum agent step count per session."

    def __init__(self, max_steps: int = 50, enabled: bool = True) -> None:
        super().__init__(enabled=enabled)
        self.max_steps = max_steps

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        step_count = context.metadata.get("agent_step_count", 0)
        if isinstance(step_count, int) and step_count >= self.max_steps:
            return self._block(
                f"Agent step limit reached: {step_count} >= {self.max_steps}",
                step_count=step_count,
                limit=self.max_steps,
            )
        return self._allow()


@registry.register
class AgentToolCallLimitRule(BaseRule):
    """Enforces a maximum number of tool calls per agent session."""

    rule_id = "AG-002"
    rule_name = "Agent Tool Call Limit"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.HIGH
    default_action = GuardAction.BLOCK
    description = "Enforces maximum tool call count per agent session."

    def __init__(self, max_tool_calls: int = 100, enabled: bool = True) -> None:
        super().__init__(enabled=enabled)
        self.max_tool_calls = max_tool_calls

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        tool_call_count = context.metadata.get("agent_tool_call_count", 0)
        if isinstance(tool_call_count, int) and tool_call_count >= self.max_tool_calls:
            return self._block(
                f"Agent tool call limit reached: {tool_call_count} >= {self.max_tool_calls}",
                tool_call_count=tool_call_count,
                limit=self.max_tool_calls,
            )
        return self._allow()


@registry.register
class AgentRecursionDepthRule(BaseRule):
    """Enforces a maximum recursion depth for agent sub-calls."""

    rule_id = "AG-003"
    rule_name = "Agent Recursion Depth"
    category = RuleCategory.AGENT
    phase = RulePhase.VALIDATE
    default_severity = Severity.HIGH
    default_action = GuardAction.BLOCK
    description = "Enforces maximum agent recursion depth."

    def __init__(self, max_depth: int = 10, enabled: bool = True) -> None:
        super().__init__(enabled=enabled)
        self.max_depth = max_depth

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        depth = context.metadata.get("agent_recursion_depth", 0)
        if isinstance(depth, int) and depth >= self.max_depth:
            return self._block(
                f"Agent recursion depth exceeded: {depth} >= {self.max_depth}",
                depth=depth,
                limit=self.max_depth,
            )
        return self._allow()


class AgentPolicy(BasePolicy):
    """Policy for agent session limits and safety (includes ASI09 and ASI10 controls)."""

    def __init__(
        self,
        enabled: bool = True,
        max_steps: int = 50,
        max_tool_calls: int = 100,
        max_depth: int = 10,
        # ASI09 controls
        enable_confirmation_prompts: bool = True,
        enable_evidence_requirements: bool = True,
        enable_content_marking: bool = True,
        enable_manipulation_detection: bool = True,
        enable_decision_escalation: bool = True,
        # ASI10 controls
        enable_behavioral_baseline: bool = True,
        enable_kill_switch: bool = True,
        enable_policy_protection: bool = True,
        enable_persistence_detection: bool = True,
        enable_dual_control: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self.max_steps = max_steps
        self.max_tool_calls = max_tool_calls
        self.max_depth = max_depth
        # ASI09
        self.enable_confirmation_prompts = enable_confirmation_prompts
        self.enable_evidence_requirements = enable_evidence_requirements
        self.enable_content_marking = enable_content_marking
        self.enable_manipulation_detection = enable_manipulation_detection
        self.enable_decision_escalation = enable_decision_escalation
        # ASI10
        self.enable_behavioral_baseline = enable_behavioral_baseline
        self.enable_kill_switch = enable_kill_switch
        self.enable_policy_protection = enable_policy_protection
        self.enable_persistence_detection = enable_persistence_detection
        self.enable_dual_control = enable_dual_control

    def get_rules(self) -> list[BaseRule]:
        rules: list[BaseRule] = [
            # Core agent limits
            AgentStepLimitRule(max_steps=self.max_steps),
            AgentToolCallLimitRule(max_tool_calls=self.max_tool_calls),
            AgentRecursionDepthRule(max_depth=self.max_depth),
        ]

        # ASI09: Human-Agent Trust Exploitation controls
        if self.enable_confirmation_prompts:
            rules.append(ConfirmationPromptRule())
        if self.enable_evidence_requirements:
            rules.append(EvidenceRequirementRule())
        if self.enable_content_marking:
            rules.append(ContentOriginMarkingRule())
        if self.enable_manipulation_detection:
            rules.append(ManipulativeLanguageRule())
        if self.enable_decision_escalation:
            rules.append(DecisionEscalationRule())

        # ASI10: Rogue Agents controls
        if self.enable_behavioral_baseline:
            rules.append(BehavioralBaselineRule())
        if self.enable_kill_switch:
            rules.append(AgentKillSwitchRule())
        if self.enable_policy_protection:
            rules.append(SafetyPolicyProtectionRule())
        if self.enable_persistence_detection:
            rules.append(PersistenceDetectionRule())
        if self.enable_dual_control:
            rules.append(DualControlRule())

        # Add any extra rules
        rules.extend(self._rules)

        return rules
