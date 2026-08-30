# Protect tool calls

Scan the proposed tool call, authorize it against application-owned security
context immediately before execution, then validate the response before returning
it to the model.

```python
from trustrail import Guard, GuardContext, GuardStage, ToolCall

guard = Guard.strict()
call = ToolCall(name="fetch_url", arguments={"url": requested_url})
context = GuardContext(
    stage=GuardStage.TOOL_REQUEST,
    metadata={"tool_name": call.name, "tool_args": call.arguments},
)

decision = await guard.acheck(call.name, GuardStage.TOOL_REQUEST, context=context)
if decision.is_blocked:
    raise PermissionError("Tool call rejected")

# ToolAuthorizer.require(request, budget) must also succeed here. See below.
raw_result = await execute_tool(call)
safe_result = await guard.aprotect(str(raw_result), GuardStage.TOOL_RESPONSE)
```

For function-based tools, the decorator creates the tool context automatically:

```python
@guard.tool(policy="tools")
async def fetch_url(url: str) -> str:
    return await http_client.get(url)
```

The decorator uses `inspect.signature()` binding before validation. Positional,
keyword-only, variadic, and omitted default arguments are therefore all present
in `tool_args`; bound methods exclude `self` and `cls`. The deterministic
argument representation is limited to 10,000 characters by default and rejects
unsupported or oversized structures before the tool executes. Set
`max_serialized_chars` explicitly if a tool has a larger reviewed schema.

`policy="default"` is a backwards-compatible alias for the configured `tools`
policy. Use `policy="tools"` to be explicit. Other names raise
`ConfigurationError` during decoration instead of silently being ignored. The
policy can be configured through `GuardConfig`:

```python
from trustrail import Guard, GuardConfig, GuardPolicy

guard = Guard(
    GuardConfig(
        policies={
            "tools": GuardPolicy(
                params={"allowlist": ["fetch_url"]},
            )
        }
    )
)
```

`BLOCK`, `QUARANTINE`, and `RETRY` stop execution with
`GuardrailBlockedError`. `REQUIRE_APPROVAL` stops execution with
`ApprovalRequiredError`; decorators do not perform approval themselves.

The decorator is a content guardrail, not an authorization decision. Use
`ToolAuthorizer` to bind the exact tool/version and scalar argument schema to an
authenticated principal, short-lived user intent, authoritative resource-owner
lookup, permission scopes, approval grant, and session execution budget:

```python
authorization = authorizer.require(request, budget)
try:
    raw_result = await execute_tool(authorization.tool_name, authorization.arguments)
finally:
    authorizer.complete(authorization, budget)
```

See [Excessive agency](../security/excessive-agency.md) for the complete policy
and request configuration, approval workflow, limitations, and residual risk.
Also enforce least-privilege credentials, network egress, timeouts, quotas, and
resource ownership in the downstream service.
