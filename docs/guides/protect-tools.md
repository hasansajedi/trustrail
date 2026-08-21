# Protect tool calls

Validate the proposed tool name and arguments before execution, then validate the
tool response before returning it to the model.

```python
from aiRail import Guard, GuardContext, GuardStage, ToolCall

guard = Guard.strict()
call = ToolCall(name="fetch_url", arguments={"url": requested_url})
context = GuardContext(
    stage=GuardStage.TOOL_REQUEST,
    metadata={"tool_name": call.name, "tool_args": call.arguments},
)

decision = await guard.acheck(call.name, GuardStage.TOOL_REQUEST, context=context)
if decision.is_blocked:
    raise PermissionError("Tool call rejected")

raw_result = await execute_tool(call)
safe_result = await guard.aprotect(str(raw_result), GuardStage.TOOL_RESPONSE)
```

For function-based tools, the decorator creates the tool context automatically:

```python
@guard.tool()
async def fetch_url(url: str) -> str:
    return await http_client.get(url)
```

The decorator is a guardrail, not an authorization system. Enforce schemas,
allowlists, tenant permissions, network egress rules, timeouts, and resource
limits in the tool implementation itself.
