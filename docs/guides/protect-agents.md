# Protect agents

Agents need both content checks and hard execution budgets. `agent_session`
tracks steps, tool calls, recursion depth, and wall-clock duration.

```python
from trustrail import Guard, GuardContext, GuardStage, ToolCall

guard = Guard.strict()
context = GuardContext(
    session_id="agent-123",
    user_id="user-42",
    stage=GuardStage.AGENT_ACTION,
)

async with guard.agent_session(
    context,
    max_steps=20,
    max_tool_calls=10,
    max_depth=3,
    max_duration_seconds=60,
) as session:
    step_result = await session.step(model_plan)
    if step_result.is_blocked:
        raise RuntimeError("Unsafe agent plan")

    call = ToolCall(name="search", arguments={"query": "Python docs"})
    tool_result = await session.validate_tool_call(call)
    if tool_result.is_blocked:
        raise RuntimeError("Unsafe tool call")
```

Call `enter_recursion()` and `exit_recursion()` around nested agent execution.
Treat `GuardrailBlockedError` from a budget limit as terminal for that session.

Keep authorization outside the model: allowlist tools per user, validate typed
arguments, require approval for high-impact operations, use least-privilege
credentials, and make write operations idempotent where possible.

Do not expose a persistent-memory write tool directly to the model. Use
`authorize_memory_write()` and store the returned normalized/redacted value only
after the configured approval provider accepts it. See
[Protect persistent memory](protect-memory.md).
