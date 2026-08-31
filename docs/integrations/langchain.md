# LangChain integration

```bash
python -m pip install "trustrail[langchain]"
```

Use `TrustRailCallbackHandler` for synchronous chains. Guard errors propagate
through LangChain's callback manager so a blocked prompt or tool input stops the
provider call.

```python
from trustrail import Guard
from trustrail.integrations.langchain import TrustRailCallbackHandler

guard = Guard.balanced()
handler = TrustRailCallbackHandler(guard)

result = chain.invoke(
    {"input": user_input},
    config={
        "callbacks": [handler],
        "metadata": {"tenant_id": tenant_id, "request_id": request_id},
        "tags": ["production"],
    },
)
```

For `ainvoke()` and other async LangChain APIs, use the native async handler.
Its callback methods await `Guard.acheck()` before returning; no detached guard
tasks are created.

```python
from trustrail.integrations.langchain import TrustRailAsyncCallbackHandler

async_handler = TrustRailAsyncCallbackHandler(guard)
result = await chain.ainvoke(
    {"input": user_input},
    config={
        "callbacks": [async_handler],
        "metadata": {"tenant_id": tenant_id, "request_id": request_id},
    },
)
```

The handlers check LLM prompts, generated text, and tool inputs. Prompt lists
and mutable generation objects receive redacted or transformed values in place.
LangChain tool-start callback arguments cannot be replaced; if a tool input
requires transformation, the handler blocks rather than allowing the original
value through.

Unexpected guard or provider errors follow `GuardConfig.fail_mode`:

- `CLOSED` raises `GuardrailBlockedError` before the framework boundary.
- `OPEN` logs only the exception type and allows the original value.

Cancellation always propagates to the awaited guard check. LangChain `run_id`,
`parent_run_id`, tags, and request/session/user/tenant identifiers are carried
into `GuardContext` for audit correlation.

`AegisRailCallbackHandler` and `AegisRailAsyncCallbackHandler` remain aliases
for compatibility. New code should use the TrustRail-named classes.
