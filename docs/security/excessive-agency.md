# Excessive agency

Excessive agency occurs when an agent can take more actions, use more privileges,
or run longer than required. Content filtering alone cannot prevent it.

trustrail provides two complementary layers of enforcement: **session-level budgets**
through `AgentSession`, and **standalone rules** that can be applied at any
`AGENT_ACTION` or `TOOL_REQUEST` guard stage.

## Session-level budgets

```python
async with guard.agent_session(
    context,
    max_steps=20,
    max_tool_calls=10,
    max_depth=3,
    max_duration_seconds=60,
) as session:
    result = await session.step(plan)
    tool_result = await session.validate_tool_call(tool_call)
```

## Standalone rules

Three rules address excessive agency and can be used independently of
`AgentSession` by adding them to a `Guard` or policy:

### EA-001 `AgentStepLimitRule`

Blocks execution when `agent_step` in `context.metadata` reaches or exceeds
`max_steps`. Use this to cap the total number of sequential steps an agent may
take, regardless of how the orchestration framework tracks them.

```python
from trustrail.rules.tools import AgentStepLimitRule

rule = AgentStepLimitRule(max_steps=25)
context = GuardContext(
    stage=GuardStage.AGENT_ACTION,
    metadata={"agent_step": current_step},
)
result = rule.evaluate("", context)
```

### EA-002 `ToolCallFrequencyRule`

Rate-limits tool invocations per session within a sliding time window. Tracks
call timestamps in-process; pass a consistent `session_id` on `GuardContext`
for accurate per-session enforcement.

```python
from trustrail.rules.tools import ToolCallFrequencyRule

rule = ToolCallFrequencyRule(max_calls=50, window_seconds=60.0)
# Call rule.evaluate() before every tool invocation
result = rule.evaluate("", context)
```

### EA-003 `RecursionDepthRule`

Blocks execution when `recursion_depth` in `context.metadata` reaches or
exceeds `max_depth`. Prevents runaway recursive loops in multi-agent or
self-calling tool patterns.

```python
from trustrail.rules.tools import RecursionDepthRule

rule = RecursionDepthRule(max_depth=10)
context = GuardContext(
    stage=GuardStage.AGENT_ACTION,
    metadata={"recursion_depth": current_depth},
)
result = rule.evaluate("", context)
```

## Application controls

- Allowlist tools and arguments for each user and tenant.
- Use separate read-only and write-capable credentials.
- Require human approval for irreversible or high-value actions.
- Cap cost, tokens, retries, concurrency, and external requests.
- Record action intent and result in an append-only audit log.
- Make tools idempotent and support cancellation or rollback.

Terminate the workflow when a session budget raises
`GuardrailBlockedError`; starting a fresh session automatically would defeat the
limit.
