"""Custom policy and rule example."""

from typing import ClassVar

from trustrail import Guard, GuardStage
from trustrail.models.core import GuardContext, GuardDecision
from trustrail.models.enums import GuardAction, RuleCategory, RulePhase, Severity
from trustrail.rules.base import BaseRule


class CompetitorMentionRule(BaseRule):
    """Custom rule: warns when competitors are mentioned."""

    rule_id = "CUSTOM-001"
    rule_name = "Competitor Mention"
    category = RuleCategory.CONTENT_SAFETY
    phase = RulePhase.DETECT
    default_severity = Severity.LOW
    default_action = GuardAction.WARN
    description = "Warns when competitor names are mentioned in output."

    COMPETITORS: ClassVar[list[str]] = ["CompetitorA", "CompetitorB", "RivalCorp"]

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        for competitor in self.COMPETITORS:
            if competitor.lower() in value.lower():
                return self._block(
                    f"Competitor '{competitor}' mentioned in output",
                    severity=Severity.LOW,
                    action=GuardAction.WARN,
                    competitor=competitor,
                )
        return self._allow()


# Add custom rule to guard
guard = Guard.balanced(extra_rules=[CompetitorMentionRule()])

texts = [
    "Our product is the best solution for your needs.",
    "You should check out CompetitorA, they have great features.",
    "Python is a great programming language.",
]

for text in texts:
    result = guard.check(text, GuardStage.LLM_RESPONSE)
    status = "WARN" if result.action.value == "warn" else result.action.value.upper()
    print(f"[{status}] {text!r}")
