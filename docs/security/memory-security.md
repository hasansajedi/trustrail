# Persistent memory security

Long-lived memory is a security boundary. An attacker can ask an agent to remember
malicious instructions, false identity claims, credentials, or preferences that
change later sessions. Treat model-proposed memory as untrusted even when it
appears to quote the user.

## Required controls

1. Keep the memory backend inaccessible to the model and its tools by default.
2. Call `authorize_memory_write()` before every persistent write.
3. Bind approval to the authenticated user, tenant, target key, and session outside
   the model.
4. Present the normalized/redacted value and its classification to the approver.
5. Record the approval decision separately without logging the memory content.
6. Re-scan memory at `MEMORY_READ` before placing it in an LLM request.
7. Support expiry, user inspection, correction, and deletion.

`MEM-001` returns `REQUIRE_APPROVAL` for persistent `general`, `preference`,
`profile`, and `instruction` writes. Credential- or secret-like memory is blocked.
Prompt-injection and sensitive-data policies run before classification, so an
approval cannot override a security block.

The classifier is a policy signal, not proof that the proposed fact is accurate or
belongs to the current user. Authorization and ownership checks must use trusted
application state. Never accept an approval token, trust label, or persistence flag
from model-generated content.

When memory can also arrive from imports, tools, agents, or another service, run a
typed `DataIngestionRecord` through `DataPoisoningVerifier.require()` first. This
binds the write to allowed source, writer, tenant, purpose, version, integrity,
lineage, and anomaly policy. Human approval is still required afterward. See
[Data and model poisoning](data-model-poisoning.md).

Audit events contain the stage, action, input length, and finding identifiers, not
the proposed memory. The initial event records `required`; a second event records
`approved`, `denied`, `missing_provider`, or `provider_error`, together with the
content-free classification. The approval provider necessarily receives the safe
candidate for human review; protect that channel as sensitive application data.

## Persistent taint and lineage controls

`MemoryTaintManager` addresses persistent-memory poisoning across transformations
and later sessions. `MemoryRecord` integrity-binds a content digest to:

- source provenance and trust, writer and owner identity;
- tenant, audience scope, and declared purpose;
- direct, summary, merge, embedding, migration, or rebuild transformation;
- exact dependency revisions and inherited taint signals;
- review state, approval identifier, version, and expiry.

The manager detects direct instruction, role, security-policy, and delayed-trigger
content after Unicode normalization and Base64 extraction. It also retains a
bounded, tenant/user/purpose-isolated normalized history to detect instructions
split over multiple writes. Derived writes fail closed when they drop source
provenance, hide inherited taint through a summary or merge, bind a missing or stale
dependency, or cross a tenant or purpose boundary. Untrusted sources and shared
scope are privileged even when their text looks benign.

Privileged writes require an application-provided `MemoryApprovalVerifier`. It must
authenticate the approver from trusted state; an approval is short-lived,
single-use, and bound to the exact request digest, tenant, and full detected-signal
set. High-confidence integrity, cross-user, split-entry, laundering, provenance, and
inherited-taint failures are non-overridable.

Writes use a two-phase boundary: authorize and reserve the exact proposal, persist
the bytes, then pass the confirmed stored bytes to `commit_write()`. If storage
fails, call `abandon_write()`. Retrieval is atomic across the selected set and
checks ownership, tenant, purpose, expiry, status, dependency revisions, and exact
content digests before any bytes enter a prompt. A newly discovered integrity or
composed split-entry failure quarantines the affected memory and all transitive
dependents.

`quarantine()` and `invalidate()` trace the dependency graph and produce a
content-free `MemoryRebuildPlan`. A `MemoryRebuildHook` can queue reconstruction
from independently trusted provenance. `revalidate()` requires an authenticated,
exact-revision `MemoryRevalidationGrant`, clean current content, and safe unchanged
dependencies. Revalidating a root does not make stale descendants safe; rebuild
them with new dependency digests.

### Configuration

At minimum configure `allowed_purpose_ids`. Configure `trusted_writer_ids` from
authenticated application identities, not model claims. `privileged_signals` and
`non_overridable_signals` are disjoint policy sets; weakening either is a security
decision. `authorization_ttl_seconds`, `max_recent_entries`, `max_history_chars`,
`max_dependencies`, and `max_provenance_sources` bound replay windows and local
state. Audit or rebuild callback failure cannot turn a denied operation into an
allowed one and never exposes memory content; callback delivery itself needs
application monitoring and retry.

### Assumptions, limitations, and residual risk

- Manager catalog, replay, dependency, and split-history state is process-local.
  Multi-worker or multi-region deployments must implement equivalent shared,
  atomic, durable state at the persistence boundary.
- Trustrail stores metadata and bounded normalized fragments in memory; the
  application remains responsible for encryption, retention, access control,
  deletion, and protecting raw memory bytes and review channels.
- Pattern detection cannot prove factual correctness or detect every multilingual,
  semantic, steganographic, or model-specific poison. Apply source verification,
  domain validation, monitoring, and red-team evaluation.
- A trusted writer, approval verifier, revalidation verifier, or authoritative
  source can still be compromised. Use workload identity, least privilege, short
  lifetimes, protected signing/verification state, and incident response.
- Memory authorization does not replace prompt-injection checks at read time,
  service-side authorization, RAG provenance controls, output validation, or tool
  authorization. Continue applying those controls after retrieval.

See [Protect persistent memory](../guides/protect-memory.md) for an end-to-end API
example.
