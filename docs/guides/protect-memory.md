# Protect persistent memory

Persistent memory can turn one injected response into durable behavior. Route every
write through `authorize_memory_write`; do not let a model write directly to the
memory backend.

```python
from trustrail import Guard, GuardContext, GuardStage


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

## Preserve trust across the full memory lifecycle

`authorize_memory_write()` protects one candidate. Applications that summarize,
merge, embed, migrate, share, or retrieve long-lived memory should additionally use
`MemoryTaintManager`. Its metadata envelope binds the content digest to the writer,
owner, tenant, purpose, provenance, transformation, dependency revisions, taint
signals, and approval. The content itself remains in your backend.

```python
from datetime import UTC, datetime

from trustrail import (
    MemoryContentKind,
    MemoryProvenance,
    MemoryReadRequest,
    MemoryRecord,
    MemoryScope,
    MemorySourceKind,
    MemoryTaintManager,
    MemoryTaintPolicy,
    MemoryTransformationKind,
    MemoryWriteRequest,
    TrustLevel,
)

now = datetime.now(UTC)
content = "The account uses monthly billing."
provenance = MemoryProvenance(
    source_id="account-row-42",
    source_kind=MemorySourceKind.TOOL,
    trust_level=TrustLevel.TRUSTED,
    writer_id="memory-service",
    tenant_id="tenant-a",
    purpose_id="assistant-memory",
    observed_at=now,
)
record = MemoryRecord.create(
    content=content,
    memory_id="billing-cadence",
    tenant_id="tenant-a",
    owner_user_id="user-42",
    writer_id="memory-service",
    purpose_id="assistant-memory",
    content_kind=MemoryContentKind.FACT,
    scope=MemoryScope.USER,
    transformation=MemoryTransformationKind.DIRECT,
    provenance=(provenance,),
    created_at=now,
)
request = MemoryWriteRequest.create(
    request_id="write-42",
    actor_id="memory-service",
    actor_user_id="user-42",
    tenant_id="tenant-a",
    purpose_id="assistant-memory",
    record=record,
)
manager = MemoryTaintManager(
    MemoryTaintPolicy(
        trusted_writer_ids=frozenset({"memory-service"}),
        allowed_purpose_ids=frozenset({"assistant-memory"}),
    )
)

# Reserve first, persist the exact bytes, then commit their catalog metadata.
lease = manager.require_write(request, content, now=now)
await memory_backend.set(record.memory_id, content)
stored_content = await memory_backend.get(record.memory_id)
manager.commit_write(lease, stored_content, now=now)

# Authorize all selected records and bytes atomically before prompt assembly.
read = MemoryReadRequest(
    request_id="read-42",
    reader_id="assistant-service",
    reader_user_id="user-42",
    tenant_id="tenant-a",
    purpose_id="assistant-memory",
    memory_ids=(record.memory_id,),
)
manager.require_retrieval(read, {record.memory_id: stored_content}, now=now)
```

Instruction-bearing, role-changing, security-policy, delayed-trigger, shared-scope,
and untrusted-source writes require a short-lived `MemoryWriteApproval` authenticated
by your `MemoryApprovalVerifier`. Approvals are bound to the exact request and risk
signals and cannot authorize split-entry, cross-user, provenance-loss, laundering,
dependency, or integrity failures.

For every derived record, declare `MemoryDependency` edges using each input's exact
`record_digest`, carry the union of its provenance and taint signals, and identify
the transformation. At retrieval, use the exact bytes returned by the backend. A
single unsafe selection fails the entire read and newly detected tampering
quarantines transitive dependents.

On incidents, call `quarantine()` or `invalidate()`. Both return a
`MemoryRebuildPlan` and notify an optional `MemoryRebuildHook`; rebuild only from the
listed independently authoritative sources, never from quarantined memory.
