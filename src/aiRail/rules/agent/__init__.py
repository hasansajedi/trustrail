"""Agent safety rules for ASI09 and ASI10."""

from trustrail.rules.agent.asi09 import (
    ConfirmationPromptRule,
    ContentOriginMarkingRule,
    DecisionEscalationRule,
    EvidenceRequirementRule,
    ManipulativeLanguageRule,
)
from trustrail.rules.agent.asi10 import (
    AgentKillSwitchRule,
    BehavioralBaselineRule,
    DualControlRule,
    PersistenceDetectionRule,
    SafetyPolicyProtectionRule,
)

__all__ = [
    "AgentKillSwitchRule",
    "BehavioralBaselineRule",
    "ConfirmationPromptRule",
    "ContentOriginMarkingRule",
    "DecisionEscalationRule",
    "DualControlRule",
    "EvidenceRequirementRule",
    "ManipulativeLanguageRule",
    "PersistenceDetectionRule",
    "SafetyPolicyProtectionRule",
]
