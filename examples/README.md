# trustrail examples

This folder is the runnable companion to the documentation. Start with
[`basic_input.py`](basic_input.py), then choose the boundary that matches where
untrusted or model-generated data enters your application.

Run an example from the repository root:

```bash
uv run python examples/basic_input.py
# or, after installing trustrail:
python examples/basic_input.py
```

Most examples need only the base package. Optional framework integrations have
their installation extra listed below. The examples use local stand-ins instead
of making network calls, writing persistent data, or executing model-proposed
tools.

## Core guard workflows

| Need | Runnable example | What it demonstrates |
| --- | --- | --- |
| Check user input | [`basic_input.py`](basic_input.py) | Decisions, scores, and finding IDs |
| Configure policies and audit | [`configuration_and_audit.py`](configuration_and_audit.py) | Redaction, authenticated context, and content-free audit events |
| Guard function arguments | [`decorators.py`](decorators.py) | Fully bound arguments and forwarding transformed values |
| Protect a conversation atomically | [`conversation.py`](conversation.py) | Role-specific stages, tool relationships, and fail-closed rejection |
| Protect composed prompts | [`prompt_boundaries.py`](prompt_boundaries.py) | Source labels and cross-segment injection detection |
| Add an application rule | [`custom_policy.py`](custom_policy.py) | A typed `BaseRule` attached to a guard |
| Scan generated output | [`output_handling.py`](output_handling.py) | Final guard check plus destination-specific HTML, JSON, and SQL handling |
| Scan streamed output | [`streaming.py`](streaming.py) | Cross-chunk checks and emitting only `safe_chunk` |

## RAG, data, and model integrity

| Need | Runnable example | What it demonstrates |
| --- | --- | --- |
| Protect retrieved documents | [`rag_example.py`](rag_example.py) | Document scanning and a provenance-labeled RAG envelope |
| Secure vector retrieval | [`secure_vector_workflow.py`](secure_vector_workflow.py) | Authorization, lineage, similarity, and context assembly |
| Verify data before indexing | [`data_poisoning.py`](data_poisoning.py) | Source, writer, tenant, version, and content checks |
| Verify AI components | [`supply_chain.py`](supply_chain.py) | Approved provenance and digest pinning before use |
| Ground factual output | [`evidence_grounding.py`](evidence_grounding.py) | Claims, citations, trusted evidence, and assessor confidence |
| Protect system prompts | [`system_prompt_security.py`](system_prompt_security.py) | Classified prompt construction and output leakage detection |

## Agents and operational controls

| Need | Runnable example | What it demonstrates |
| --- | --- | --- |
| Bound an agent run | [`agent.py`](agent.py) | Step, tool-call, recursion, and duration budgets |
| Preserve an agent goal | [`goal_integrity.py`](goal_integrity.py) | Integrity-bound plans, delegation, mutation approval, and content-free audit |
| Delegate an agent identity | [`delegated_identity.py`](delegated_identity.py) | Short-lived identity chains with scope, audience, purpose, tenant, and depth narrowing |
| Authorize a tool | [`tool_authorization.py`](tool_authorization.py) | Capability, identity, intent, ownership, and execution budget |
| Verify tool semantics | [`semantic_tool_authorization.py`](semantic_tool_authorization.py) | Trusted argument bindings, effects, resources, and execution postconditions |
| Isolate generated code | [`isolated_code_execution.py`](isolated_code_execution.py) | Attested sandbox admission, bounded privileges, and verified output and cleanup |
| Contain dependency failures | [`cascading_failures.py`](cascading_failures.py) | Tenant-isolated circuits, trusted fallbacks, and authenticated outcomes |
| Bound model resources | [`resource_budget.py`](resource_budget.py) | Reservation, completion, and failure cleanup |
| Rate-limit one process | [`rate_limiting.py`](rate_limiting.py) | Atomic fixed-window admission and collision-safe identity keys |
| Rate-limit multiple workers | [`redis_rate_limiting.py`](redis_rate_limiting.py) | Shared Redis state, fail mode, pooling, and shutdown |
| Approve persistent memory | [`persistent_memory.py`](persistent_memory.py) | Redaction before out-of-band approval and storage |
| Track persistent-memory taint | [`memory_taint.py`](memory_taint.py) | Provenance, exact-byte commit, retrieval checks, and content-free audit events |
| Add an adaptive CI gate | [`red_team_gate.py`](red_team_gate.py) | Deterministic attack mutations and regression thresholds |

## Provider and framework adapters

| Need | Runnable example | What it demonstrates |
| --- | --- | --- |
| Run external safety checks | [`async_providers.py`](async_providers.py) | Awaited moderation and RAG grounding with per-provider deadlines and fail modes |

[`openai_messages.py`](openai_messages.py) runs without an API key or network
call and demonstrates preserving multipart content and tool-call fields. Install
`trustrail[openai]` when using the returned messages with the OpenAI SDK.

Framework adapters need their corresponding ecosystem and application objects,
so their maintained examples live in the integration guides:

- [FastAPI middleware and dependency injection](../docs/integrations/fastapi.md)
  — install `trustrail[fastapi]`.
- [LangChain synchronous and awaited callbacks](../docs/integrations/langchain.md)
  — install `trustrail[langchain]`.
- [LlamaIndex synchronous and awaited boundaries](../docs/integrations/llamaindex.md)
  — install `trustrail[llamaindex]`.
- [OpenTelemetry audit export](../docs/observability.md) — install
  `trustrail[otel]`.
- [External safety providers](../docs/integrations/external-safety-providers.md)
  — moderation, DLP, prompt-injection, and grounding adapters.
- [Redis-backed distributed rate limiting](../docs/guides/rate-limiting.md) —
  install `trustrail[redis]`.

## Production checklist

The examples show library boundaries, not a complete deployment. In production:

- derive user, tenant, session, ownership, and scope values from authenticated
  server-side state—not prompts, model output, or retrieved metadata;
- use every returned safe/transformed value downstream; never scan one value and
  then forward the original;
- reject atomically when a conversation, RAG envelope, or tool request fails;
- keep provider timeouts, request-size limits, authorization, sandboxing, output
  encoding, database parameterization, and network egress controls enabled;
- use Redis or another atomic shared backend for cross-process limits; and
- turn red-team findings and production incidents into regression corpus cases.

See the [quick start](../docs/quickstart.md),
[threat model](../docs/security/threat-model.md), and
[guardrail lifecycle](../docs/guardrail-lifecycle.md) for the assumptions around
these examples.
