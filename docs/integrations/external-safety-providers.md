# External safety providers

Use the async provider pipeline for remote moderation, prompt-injection
detection, DLP/redaction, and RAG grounding. Provider calls run on the event loop,
are bounded by deadlines and concurrency limits, and produce ordinary
`GuardFinding` values in the final `GuardResult`.

## Register a moderation provider

Implement the typed protocol and register it with a stable ID. Provider IDs,
finding messages, and finding metadata must never contain credentials or raw
sensitive values.

```python
from trustrail import (
    ContentSafetyProvider,
    FailMode,
    Guard,
    GuardConfig,
    GuardStage,
    ProviderRegistration,
)

moderation: ContentSafetyProvider = MyModerationAdapter(client)

guard = Guard(
    GuardConfig(
        provider_timeout_seconds=3.0,
        max_async_concurrency=8,
    ),
    content_safety_providers=[
        ProviderRegistration(
            provider_id="primary-moderation",
            provider=moderation,
            timeout_seconds=1.5,
            fail_mode=FailMode.CLOSED,
        )
    ],
)

result = await guard.acheck(model_output, GuardStage.FINAL_OUTPUT)
if result.is_blocked:
    reject_response(result.findings)
else:
    send_response(result.output_value)
```

An adapter must return `list[GuardFinding]`. Content moderation findings use
`RuleCategory.CONTENT_SAFETY`; prompt-injection adapters may use
`PROMPT_INJECTION` or `JAILBREAK`. A provider returning another category is
treated as a provider failure so it cannot escape its configured policy.

## Verify RAG output against documents

Grounding verifiers receive the generated response and the exact retrieved
`Document` objects supplied by the application:

```python
from trustrail import Document, GuardStage, TrustLevel

documents = [
    Document(
        content=item.text,
        source=item.source,
        source_url=item.url,
        trust_level=TrustLevel.UNTRUSTED,
    )
    for item in search_results
]

safe_documents = []
for document in documents:
    scan = await guard.acheck_document(document)
    if not scan.is_blocked:
        safe_documents.append(document.model_copy(update={"content": scan.output_value}))

result = await guard.acheck(
    generated_response,
    GuardStage.LLM_RESPONSE,
    documents=safe_documents,
)
safe_response = result.output_value
```

Register an implementation of `GroundingVerifier` through
`grounding_verifiers`. Its findings must use `RuleCategory.GROUNDING`. Omitting
`documents` is a provider failure governed by that verifier's fail mode; it is
not interpreted as evidence that the response is grounded.

## Execution order

One call has four ordered phases:

1. Built-in and custom synchronous rules run first. A blocked result prevents
   external calls.
2. Async rules declared as `NORMALIZE` or `TRANSFORM` run sequentially in
   registration order. Each receives the previous safe value.
3. Sensitive-data providers run sequentially and redact before any independent
   provider sees the value.
4. Remaining async rules and content-safety, prompt-injection, and grounding
   providers run concurrently against the final transformed value.

Independent checks cannot return `REDACT` or `TRANSFORM`; use an async transform
rule or sensitive-data provider for value changes. Concurrent completion timing
does not affect the returned order: async-rule findings retain rule registration
order, followed by providers in their stable kind and registration order.

## Deadlines, cancellation, and fail modes

`GuardConfig.provider_timeout_seconds` is the default deadline for each async
rule or provider. Override it per registration with `timeout_seconds`.
`GuardConfig.timeout_seconds` still bounds the complete check, including all
sync and async phases. `max_async_concurrency` limits in-flight independent
checks for one evaluation.

`FailMode.CLOSED` turns a timeout, invalid result, or exception into a blocking
content-free finding. `FailMode.OPEN` returns a warning finding and continues.
Failure findings record only the configured check ID, check kind, and whether
the failure was a timeout or exception; exception messages are not copied to
results or audit events.

Cancelling `Guard.acheck()` cancels its in-flight provider tasks. Adapters should
not suppress `asyncio.CancelledError`, and their HTTP client should also have a
transport-level timeout.

## Synchronous callers

`Guard.check()` raises `AsyncGuardRequiredError` when an async rule or provider
applies to the requested stage. This avoids silently skipping a remote safety
control. Use `await guard.acheck(...)`, including from async decorators and
framework handlers. `check()` remains available for stages where none of the
registered async checks apply.

The complete runnable local example is
[`examples/async_providers.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/async_providers.py).
