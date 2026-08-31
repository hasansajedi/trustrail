# Custom rules

Create a `BaseRule` when an application has domain constraints that the built-in
policies cannot express. A rule receives text plus a `GuardContext` and returns a
typed `GuardDecision`.

```python
from trustrail import Guard, GuardContext, GuardStage
from trustrail.models import GuardDecision, RuleCategory, Severity
from trustrail.rules.base import BaseRule


class InternalProjectNameRule(BaseRule):
    rule_id = "ORG-001"
    rule_name = "Internal project name"
    category = RuleCategory.SENSITIVE_DATA
    default_severity = Severity.HIGH
    description = "Prevents internal project names from leaving the system"

    def evaluate(self, value: str, context: GuardContext) -> GuardDecision:
        if "project lighthouse" in value.casefold():
            return self._block("Internal project name detected")
        return self._allow()


guard = Guard.balanced(extra_rules=[InternalProjectNameRule()])
result = guard.check("Project Lighthouse status", GuardStage.FINAL_OUTPUT)
assert result.is_blocked
```

## Design requirements

- Assign a stable, unique `rule_id`; logs and allowlists depend on it.
- Return `_allow()` when no violation is found.
- Include a clear remediation-oriented finding message.
- Keep evaluation deterministic and bounded in time.
- Avoid placing secrets or complete sensitive values in finding metadata.
- Test benign input as thoroughly as blocked input to control false positives.

## Testing a rule

```python
from trustrail import GuardContext


def test_blocks_internal_name() -> None:
    decision = InternalProjectNameRule().evaluate(
        "Project Lighthouse status",
        GuardContext(),
    )
    assert decision.action.value == "block"


def test_allows_normal_text() -> None:
    decision = InternalProjectNameRule().evaluate("Public roadmap", GuardContext())
    assert decision.action.value == "allow"
```

See the [rules API](api/rules.md) for available helpers and class attributes.

## Async rules

Subclass `BaseAsyncRule` when a rule must await application or remote I/O. Set
its phase explicitly when it transforms the value; detector rules run
concurrently and cannot transform.

```python
from trustrail import (
    AsyncRuleRegistration,
    FailMode,
    Guard,
    GuardStage,
    RuleCategory,
    RulePhase,
)
from trustrail.models import GuardAction, GuardDecision
from trustrail.rules.base import BaseAsyncRule


class TenantVocabularyRule(BaseAsyncRule):
    rule_id = "ORG-ASYNC-001"
    rule_name = "Tenant vocabulary normalization"
    category = RuleCategory.CONTENT_SAFETY
    phase = RulePhase.TRANSFORM

    async def evaluate(self, value, context):
        replacement = await vocabulary_service.normalize(context.tenant_id, value)
        return GuardDecision(
            action=GuardAction.TRANSFORM,
            transformed_value=replacement,
            rule_id=self.rule_id,
        )


guard = Guard(
    async_rules=[
        AsyncRuleRegistration(
            TenantVocabularyRule(),
            timeout_seconds=0.5,
            fail_mode=FailMode.CLOSED,
        )
    ]
)
result = await guard.acheck(text, GuardStage.USER_INPUT)
```

Runtime `RuleConfig` controls—enablement, action, severity, confidence threshold,
and validated constructor parameters—also apply to `BaseAsyncRule`. Cancelling
`acheck()` propagates cancellation to the rule. See
[external safety providers](integrations/external-safety-providers.md) for the
full execution contract.
