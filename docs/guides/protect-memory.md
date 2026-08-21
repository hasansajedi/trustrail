# Protect persistent memory

Persistent memory can turn one injected response into durable behavior. Route every
write through `authorize_memory_write`; do not let a model write directly to the
memory backend.

```python
from aiRail import Guard, GuardContext, GuardStage


class ReviewQueue:
    async def request_approval(self, value, context=None, reason=""):
        return await review_ui.confirm(value=value, reason=reason)


guard = Guard(approval_provider=ReviewQueue())
context = GuardContext(
    stage=GuardStage.MEMORY_WRITE,
    user_id="user-42",
    session_id="session-123",
)

safe_value = await guard.authorize_memory_write(
    proposed_memory,
    persistent=True,
    context=context,
)
await memory_backend.set(memory_key, safe_value)
```

The guard normalizes invisible Unicode, blocks prompt injection and secret-like
content, redacts supported PII, and classifies the remaining value as `general`,
`preference`, `profile`, or `instruction`. Every persistent write requires the
configured approval provider to return `True`. Missing, failed, or denied approval
does not authorize a write.

Use `check_memory_write()` when an application needs the classification finding
before starting its own workflow. A `MEM-001` finding contains reason codes and the
classification, but never the proposed memory text.

Set `persistent=False` only for working state that is not written to a durable or
cross-session backend. Ephemeral values still pass through normalization,
injection detection, and sensitive-data rules.

For streamed candidates, `Guard.stream(GuardStage.MEMORY_WRITE)` withholds every
`safe_chunk` and returns `REQUIRE_APPROVAL`. Buffer the scanner's normalized final
value, then pass that value to `authorize_memory_write()`; never persist individual
chunks.
