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
workflow, such as `authorize_memory_write()`, to obtain an out-of-band decision.

For model output, stage selection describes the source but does not describe the
destination. After an allowed `LLM_RESPONSE` or `FINAL_OUTPUT` result, use
`SafeOutputHandler` with an explicit `OutputContext` before rendering, querying,
executing, opening a path, parsing structured data, or planning a tool call.
