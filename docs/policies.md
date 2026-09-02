# Policies

Policies group related rules and determine which checks apply at each point in
an LLM pipeline. `Guard` selects policies from the supplied `GuardStage`; callers
normally choose a stage instead of invoking policies directly.

| Pipeline stage | Main policy coverage |
| --- | --- |
| `USER_INPUT`, `LLM_REQUEST` | Prompt injection, sensitive data, unsafe URLs |
| `SYSTEM_PROMPT` | Sensitive data |
| `LLM_RESPONSE`, `FINAL_OUTPUT`, `STREAM` | Output safety, sensitive data |
| `RAG_DOCUMENT`, `EXTERNAL_CONTENT`, `RAG_CONTEXT` | Injection, RAG trust, supply-chain response integrity, and sensitive data |
| `TOOL_REQUEST` | Tool constraints, injection, and sensitive data |
| `TOOL_RESPONSE` | Supply-chain response integrity, output safety, and sensitive data |
| `AGENT_ACTION` | Agency limits, injection, and sensitive data |
| `MEMORY_READ` | Sensitive data |
| `MEMORY_WRITE` | Injection, sensitive data, persistent-write classification and approval |

Resource limits apply at every stage. Custom rules supplied through
`extra_rules` also run at every stage.

Text resource rules are inexpensive early warnings; they do not reserve model,
tool, or decompression capacity. Wrap expensive work with
`ResourceBudgetManager`, using authenticated principal/tenant/session identity
and exact tokenizer counts, and validate actual output before consumption. Use
`BoundedDecompressor` before parsing compressed input. See
[bounded resource consumption](security/resource-consumption.md).

Binary and metadata verification happens before these text stages. Use an
`ArtifactVerifier` to admit the component, then pass its text or response through
the appropriate `GuardStage`. Use `DataPoisoningVerifier` before data enters a
training job, RAG index, persistent store, prompt, or model loader; it validates
source policy, writer and tenant authorization, version, digest, lineage, and
anomaly evidence before the stage-specific text rules run.

## Selecting the right stage

Use the stage that describes where the value came from, not where it is going.
For example, retrieved web text is `EXTERNAL_CONTENT`, a model-generated tool
call is `TOOL_REQUEST`, and text about to be displayed to a user is
`FINAL_OUTPUT`.

```python
from trustrail import Guard, GuardContext, GuardStage, TrustLevel

guard = Guard.balanced()
context = GuardContext(
    user_id="user-123",
    request_id="req-456",
    trust_level=TrustLevel.UNTRUSTED,
)
result = guard.check(retrieved_text, GuardStage.EXTERNAL_CONTENT, context=context)
```

Treat `WARN` as a signal for logging, review, or an application-specific
confirmation step. Never silently turn `BLOCK` into `ALLOW` at a later stage.
`REQUIRE_APPROVAL` is not an allowed result; use the stage-specific authorization
workflow, such as `authorize_memory_write()` or a bound `ToolApprovalGrant`, to
obtain an out-of-band decision.

For model output, stage selection describes the source but does not describe the
destination. After an allowed `LLM_RESPONSE` or `FINAL_OUTPUT` result, use
`SafeOutputHandler` with an explicit `OutputContext` before rendering, querying,
executing, opening a path, parsing structured data, or planning a tool call.

At `TOOL_REQUEST`, content policy is defense-in-depth only. Run the typed
`ToolAuthorizer` with application-owned principal, intent, resource ownership,
scope, approval, and execution-budget state before invoking the downstream tool.

At `SYSTEM_PROMPT`, the stage policy detects sensitive text but does not control
template interpolation or retain an output reference. Construct prompts with
`SystemPromptValidator`, send only `ValidatedSystemPrompt.content`, and run
`SystemPromptLeakageDetector` against model output before delivery. See
[system prompt leakage](security/system-prompt-leakage.md).

RAG text policy does not authorize the vector query or trust similarity metadata.
Before `build_rag_context`, use `SecureVectorWorkflow` with an authenticated
principal, authoritative document/resource grants, approved indexes and
embedding models, and a protected index-entry catalog. See
[vector and embedding security](security/vector-embedding-security.md).

`MEMORY_WRITE` text policy classifies one proposal but does not persist lineage.
Use `MemoryTaintManager` whenever memory is transformed, shared, or retrieved. It
binds provenance, trust, identity, tenant, purpose, dependency revisions, and
taint metadata to exact content digests and supplies quarantine, invalidation,
revalidation, and safe-rebuild workflows. See
[persistent memory security](security/memory-security.md).

Text output policy can warn about misinformation patterns, but it cannot prove
claims or citations. Before delivering factual output or using recommendations,
run `EvidenceGroundingVerifier` with application-owned evidence, trusted
relation assessors, confidence disclosure, and independent high-impact review.
This typed verification is separate from `GuardStage` because the evidence
catalog, assessor identity, and reviewer decision must not come from generated
text. See [misinformation and unsafe overreliance](security/misinformation-overreliance.md).
