# Bounded model and agent resource consumption

OWASP LLM10:2025 covers denial of service, runaway cost, model extraction, and
resource exhaustion caused by unbounded model or agent work. Text rules help
detect large, repetitive, nested, or recursively expanding prompts. Hard limits
must also surround the actual model, tool, decompression, and session lifecycle.

## Enforcement boundary

`ResourceBudgetManager` atomically reserves work before an expensive operation
and validates actual output before it is consumed. One policy covers:

- input characters, UTF-8 bytes, exact tokenizer counts, and structure depth;
- requested and actual output tokens, characters, and bytes;
- concurrent work per authenticated principal and tenant;
- retries per stable operation ID and tool actions per session;
- cumulative session tokens and elapsed session duration;
- rolling request windows across session IDs for principal and tenant abuse;
- bounded state and replay-resistant reservation IDs;
- short-lived concurrency leases that are released on completion or cancellation.

Identity, token counts, operation IDs, and session IDs must come from trusted
application state. Do not copy them from a prompt, model response, tool
arguments, or caller-controlled metadata.

## Reserve and complete model work

```python
from trustrail import (
    ConsumptionBudgetPolicy,
    ResourceBudgetManager,
    ResourceCompletionRequest,
    ResourceIdentity,
    ResourceOperationKind,
    ResourceReservationRequest,
)

policy = ConsumptionBudgetPolicy(
    max_input_chars=100_000,
    max_input_bytes=400_000,
    max_input_tokens=8_192,
    max_output_chars=100_000,
    max_output_bytes=400_000,
    max_output_tokens=4_096,
    max_nesting_depth=100,
    max_concurrent_operations_per_principal=2,
    max_concurrent_operations_per_tenant=20,
    max_retries_per_operation=2,
    max_tool_actions_per_session=100,
    max_session_duration_seconds=300,
    max_session_tokens=100_000,
    request_window_seconds=60,
    max_requests_per_principal_window=60,
    max_requests_per_tenant_window=600,
    lease_timeout_seconds=30,
)
manager = ResourceBudgetManager(policy)
request = ResourceReservationRequest(
    reservation_id="reservation-8f71c2",
    identity=ResourceIdentity(
        principal_id=authenticated_user.id,
        tenant_id=authenticated_tenant.id,
        session_id=server_session.id,
        request_id=request_id,
        operation_id=operation_id,
    ),
    kind=ResourceOperationKind.MODEL,
    input_text=prompt,
    input_tokens=model_tokenizer.count(prompt),
    requested_output_tokens=provider_max_output_tokens,
)

lease = await manager.require_reservation(request)
try:
    response = await model.generate(
        prompt,
        max_output_tokens=request.requested_output_tokens,
        timeout=policy.lease_timeout_seconds,
    )
except BaseException:
    await manager.cancel(lease.lease_id)
    raise

safe_output = await manager.require_completion(
    ResourceCompletionRequest(
        lease_id=lease.lease_id,
        output_text=response.text,
        output_tokens=model_tokenizer.count(response.text),
    )
)
```

`require_reservation()` raises `ResourceBudgetError` before the provider call.
`require_completion()` raises if the provider ignores an output cap. Completion
and cancellation both release concurrency. A missing call is eventually released
by lease expiry, but applications should always cancel promptly in `except` and
cancellation paths.

Reservation counts are conservative: input plus requested output tokens are
charged to the session even if the response is shorter. Retries reuse the same
application-owned `operation_id` and use a fresh `reservation_id`; changing the
operation ID to bypass a denial is a security failure. Set `kind=TOOL` for each
agent tool action so the manager also enforces the tool-loop budget.

Actual output tokens must fit both the policy maximum and the smaller value
reserved for that operation. A provider response cannot borrow unused capacity
from another lease or silently exceed its request-specific generation cap.

`ResourceBudgetResult.signal` exposes low-cardinality totals for audit and
monitoring: session tokens and tool actions, principal/tenant request-window
counts, and active concurrency. Results, findings, errors, reservations, and
completion decisions do not serialize prompt or output content.

## Bounded decompression

Compressed uploads must be limited before parsing, indexing, prompt assembly, or
model use. `BoundedDecompressor` supports one gzip or zlib stream and rejects
compressed-size, decompressed-size, expansion-ratio, malformed-stream, trailing,
and concatenated-stream violations.

```python
from trustrail import (
    BoundedDecompressor,
    CompressedPayloadRequest,
    CompressionFormat,
)

decompressor = BoundedDecompressor(policy)
decoded = decompressor.require(
    CompressedPayloadRequest(
        request_id=request_id,
        format=CompressionFormat.GZIP,
        payload=compressed_body,
    )
)
```

The decoder processes compressed data incrementally and stops when a configured
output or ratio threshold is crossed. This API receives an already buffered
compressed value, so enforce HTTP content-length and streaming upload limits at
the proxy and framework before constructing the request. Disable transparent
framework decompression or apply equivalent limits at that earlier boundary.

## Guard resource rules

`Guard` applies lightweight resource rules at text stages as defense in depth:

| Rule ID | Detection |
| --- | --- |
| RL-001 | Character and optional byte length |
| RL-002 | Approximate per-value token count |
| RL-003 | Conversation message count metadata |
| RL-004 | Repetitive n-gram token bombs |
| RL-005 | Process-local cumulative token estimate |
| RL-006 | JSON/XML-like nesting depth |
| RL-007 | Process-local session request window |
| RL-008 | Repeated runs and low lexical diversity |
| RL-009 | Recursive prompt expansion instructions |

RL-001 through RL-009 are tagged `LLM10:2025`. Heuristics do not reserve actual
provider or tool capacity. In particular, RL-002 uses approximately four
characters per token, and RL-005/RL-007 are local rule-instance counters. Use
the typed manager with the deployed model's tokenizer for enforcement.

## Distributed and low-rate abuse

The included manager keeps one atomic in-process ledger. It aggregates request
windows by `(tenant_id, principal_id)` and by `tenant_id`, so changing session
IDs does not reset those limits within that ledger. Keep one manager instance
for all requests handled by a process.

Multi-process and multi-region deployments must enforce the same dimensions in
an atomic shared gateway or service. Apply hierarchical limits to IP/device,
account, API key, organization, tenant, model, endpoint, and billing project as
appropriate. Coordinate increments and concurrency leases atomically; eventual
consistency can over-admit bursts. Use longer-term quotas and anomaly detection
for attackers who stay below the rolling window, rotate identities, distribute
traffic, or attempt model extraction through many individually cheap queries.

## Operational guidance

- Reject request bytes before buffering and parse only after decompression and
  nesting checks. Apply schema limits to arrays, objects, strings, and files.
- Set provider-side input/output token caps, deadlines, cancellation, and spend
  alerts. A local timeout does not prove remote inference stopped or was not billed.
- Bound retrieval hits, source bytes, reranking, embeddings, batch size, and
  fan-out. Count hidden prompt/system/tool tokens in the provider budget.
- Apply tool-specific deadlines, response byte limits, connection pools,
  transaction limits, and downstream rate limits in addition to agent counters.
- Keep session, operation, reservation, principal, and tenant identifiers
  authenticated, opaque, stable for their intended lifetime, and unguessable
  where they authorize access. Never reuse reservation IDs.
- Emit resource codes and `ResourceUsageSignal` counters to durable monitoring.
  Alert on denials, near-limit usage, repeated lease expiry, identity churn, and
  correlated low-rate patterns without logging prompt or output content.
- Treat any exhausted budget as terminal for that operation. Do not silently
  create another session, operation, manager, or identity to retry it.

## Assumptions, limitations, and residual risk

The in-memory manager is process-local and loses counters on restart. It is not a
distributed quota store or billing system. Authenticated users can still spread
load across workers unless an upstream shared control provides atomic global
limits. State capacity intentionally fails closed; tune it and protect identity
issuance so attackers cannot exhaust tracked-session or reservation capacity.

Application-supplied token counts are trusted measurements. Use the exact
provider/model tokenizer and include cached, system, tool, image, audio, and
reasoning tokens where the provider bills them. Token budgets approximate cost;
prices, cache discounts, minimum charges, and provider accounting require a
separate monetary budget based on authoritative usage records.

The nesting scan understands JSON-style quoted strings and lightweight XML tag
shapes but is not a full parser. Enforce recursion, node, collection, entity,
schema, and parser-specific limits in the real decoder. The decompressor supports
only gzip and zlib and rejects concatenated members; archive formats, recursive
archives, media codecs, document parsers, and image dimensions need their own
sandboxed limits.

Leases limit admission, not operating-system resources. Enforce CPU, memory,
file descriptors, process counts, storage, network egress, and wall time with
infrastructure controls. Provider outages, cancellation races, queue growth,
shared dependencies, compromised credentials, Sybil identities, and novel
algorithmic-amplification prompts remain residual risks. Load-test limits and
maintain bypass-oriented corpora for each deployed model, parser, and tool.
