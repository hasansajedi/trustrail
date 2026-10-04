# Persistent workflow integrity

`WorkflowCheckpointSigner` and `PersistentWorkflowVerifier` protect long-running
agent state across serialization, process restart, failover, and resume. They
implement application-layer controls for OWASP AISVS C9.4.2 and C9.4.4:

- canonical Ed25519-signed checkpoints bind the workflow, tenant, agent,
  session, goal, plan, budgets, policy revisions, pending actions and approvals,
  current authorization, execution-chain head, and prior checkpoint;
- individually signed execution entries form an append-only predecessor chain;
- trusted resume anchors and atomic state reject insertion, deletion,
  reordering, rollback, cross-session substitution, replay, and partial restore;
- every resume rechecks signature, key status, freshness, authorization, and
  workflow/checkpoint revocation.

The signed records contain content digests rather than prompts, tool arguments,
results, credentials, or approval text. Applications persist content separately
and must compare its canonical digest with the signed binding before use.

## Configure continuity policy and signing keys

Use a control-plane key outside the agent/model runtime. The example generator
is suitable for tests; production should load or invoke a protected KMS/HSM key
without exporting private bytes.

```python
from trustrail import WorkflowCheckpointSigner, WorkflowIntegrityPolicy

signer = WorkflowCheckpointSigner.generate(authority_id="workflow-control-plane")

policy = WorkflowIntegrityPolicy(
    policy_id="production-workflow-continuity",
    version=3,
    trusted_authority_ids=frozenset({"workflow-control-plane"}),
    maximum_checkpoint_ttl_seconds=600,
    maximum_checkpoint_age_seconds=300,
    clock_skew_seconds=15,
    maximum_chain_entries=100_000,
    maximum_pending_actions=1_000,
    maximum_pending_approvals=1_000,
    resume_permit_ttl_seconds=30,
)
```

Distribute `signer.trusted_key` through authenticated configuration. Private
keys must never enter checkpoints, prompts, logs, memory, or application
configuration exposed to an agent.

## Digest state without persisting sensitive content

Use `workflow_digest()` on normalized JSON representations. The helper sorts
object keys, applies Unicode NFC normalization, rejects non-JSON values and
non-finite numbers, and hashes the canonical UTF-8 bytes.

```python
from trustrail import workflow_digest

goal_digest = workflow_digest(goal_manifest_json)
plan_digest = workflow_digest(approved_plan_json)
action_digest = workflow_digest(validated_action_json)
authorization_digest = workflow_digest(current_authorization_revision_json)
```

Keep the original values in access-controlled storage. On restore, load them
from authoritative storage, recompute the digests, and use those current values
to build `WorkflowResumeContext`. Do not trust digests supplied by the persisted
checkpoint itself as the resume context.

## Append signed execution evidence

Each entry binds its exact sequence, predecessor digest, chain/workflow identity,
tenant, agent, session, goal, plan, event kind, action, authorization, outcome,
timestamp, authority, and key. An entry after the genesis entry requires the
previous verified entry.

```python
from trustrail import WorkflowExecutionEventKind

authorized_entry = signer.sign_entry(
    chain_id="workflow-42-chain",
    entry_id="action-7-authorized",
    event_kind=WorkflowExecutionEventKind.ACTION_AUTHORIZED,
    workflow_id="workflow-42",
    tenant_id=authenticated_tenant_id,
    agent_id=authenticated_agent_id,
    session_id=authenticated_session_id,
    goal_digest=goal_digest,
    plan_digest=plan_digest,
    action_digest=action_digest,
    authorization_digest=authorization_digest,
    occurred_at=trusted_clock_now,
    prior_entry=previous_entry,
)
```

Persist the complete chain, not only its latest entry. The checkpoint commits to
both the chain length and head digest, allowing verification to distinguish
missing entries from appended uncommitted entries. Use an append-only or WORM
store where available; signatures detect tampering but do not prevent deletion.

## Sign a checkpoint

Budget and policy collections are unique and deterministically ordered. Pending
approvals must bind a matching action in `AWAITING_APPROVAL` state. Only
non-terminal actions belong in a checkpoint.

```python
from trustrail import (
    PendingActionBinding,
    PendingActionStatus,
    PendingApprovalBinding,
    WorkflowBudgetState,
    WorkflowPolicyVersion,
)

checkpoint = signer.sign_checkpoint(
    checkpoint_id="checkpoint-8",
    workflow_id="workflow-42",
    tenant_id=authenticated_tenant_id,
    agent_id=authenticated_agent_id,
    session_id=authenticated_session_id,
    goal_digest=goal_digest,
    plan_digest=plan_digest,
    budgets=(
        WorkflowBudgetState(
            budget_id="tool-calls",
            limit=20,
            consumed=7,
            reserved=1,
        ),
    ),
    policy_versions=(
        WorkflowPolicyVersion(
            policy_id="tool-policy",
            version=12,
            policy_digest=current_tool_policy_digest,
        ),
    ),
    pending_actions=pending_action_bindings,
    pending_approvals=pending_approval_bindings,
    resume_authorization_digest=authorization_digest,
    chain_id="workflow-42-chain",
    execution_chain=complete_execution_chain,
    prior_checkpoint=previous_checkpoint,
    issued_at=trusted_clock_now,
    expires_at=checkpoint_expiry,
)
```

The first checkpoint has sequence zero and no predecessor. Every later
checkpoint binds the prior checkpoint's signed digest. Store a separate trusted
anchor containing the expected checkpoint sequence/digest, prior digest, chain
ID, length, and head. Without an external anchor, an old correctly signed
checkpoint is indistinguishable from current state.

## Verify before resume

The verifier requires three trusted adapters:

- `WorkflowResumeAuthorizer` reauthorizes the exact checkpoint and current
  authorization revision at the authoritative policy/resource backend;
- `WorkflowRevocationProvider` checks current workflow and checkpoint revocation;
- `WorkflowResumeStateStore` atomically rejects replay, rollback, collisions,
  and skipped checkpoint sequences.

```python
from trustrail import PersistentWorkflowVerifier

verifier = PersistentWorkflowVerifier(
    policy,
    trusted_keys=trusted_current_and_historical_keys,
    authorizer=authoritative_resume_authorizer,
    revocation_provider=durable_revocation_provider,
    state_store=shared_atomic_resume_store,
    audit_sink=content_free_audit_sink,
)

permit = verifier.require_resume(
    persisted_state,
    trusted_resume_context,
)
```

Construct `WorkflowResumeContext` from authenticated identity, current policy
and authorization state, recomputed goal/plan digests, configured budget limits,
and the independently protected continuity anchor. Execute only the immutable
state identified by the returned `AuthorizedWorkflowResume`; never reload or
mutate persisted content between verification and execution.

`MemoryWorkflowResumeStateStore` and `MemoryWorkflowRevocationProvider` are for
tests and single-process development. Multi-worker or multi-region systems need
a shared durable implementation with atomic compare-and-set/transaction
semantics. State-service errors fail closed.

## Key rotation and revocation

New entries and checkpoints may use a rotated key while earlier chain links use
historical keys. Supply every still-trusted historical public key. Verification
checks that each key belonged to the declared authority and was active when its
record was signed.

Mark a compromised key `revoked=True`; unlike ordinary expiry, revocation makes
all records signed by it untrusted. Re-signing a checkpoint does not repair a
chain containing an untrusted historical entry. Rebuild from independently
verified evidence under incident-response procedures.

Use `WorkflowRevocationProvider` to revoke an individual checkpoint or complete
workflow independently of signing-key rotation. Revocation state must survive
process restarts and be consulted before every resume.

## Detection and audit behavior

Verification blocks:

- unsigned, forged, unknown-key, inactive-key, expired, future, over-age, or
  over-long checkpoints;
- changed tenant, agent, session, workflow, goal, plan, policy, authorization,
  budget ceiling, chain anchor, or predecessor;
- inserted, deleted, duplicated, reordered, cross-context, future-dated, or
  signature-invalid execution entries;
- expired or excessive pending actions and approvals;
- restored old checkpoints, partial chain restoration, concurrent replay,
  skipped checkpoint sequences, collisions, revocation, or live authorization
  denial/unavailability.

`WorkflowIntegrityAuditEvent` includes only one-way workflow, tenant, agent,
session, and checkpoint references plus outcome, phase, checkpoint sequence,
chain length, and time. It excludes prompts, plans, actions, results, approval
content, credentials, signatures, and raw identities.

## Security assumptions, limitations, and residual risk

- Complete mediation is required for every persist, restore, retry, failover,
  fork, approval, action, and resume path. An unsigned direct restore bypasses
  these controls.
- Protect private keys, trusted-key configuration, policy, the continuity
  anchor, revocation state, authorization providers, clocks, and atomic resume
  state independently from the agent and persisted workflow store.
- Hashes bind bytes; they do not prove that a goal, plan, action, result, policy,
  or approval is safe, authorized, truthful, complete, or free of secrets.
- An attacker who can alter both persisted state and the external trusted anchor
  can perform rollback. Use authenticated, durable, monotonic or append-only
  anchor storage with backups and independent audit.
- Process-local state cannot prevent cross-worker replay or survive restart.
  Distributed deployments require atomic shared state and conflict handling.
- Ed25519 signatures provide integrity and authority attribution, not
  confidentiality. Encrypt sensitive persisted content and minimize retention.
- Checkpoint freshness depends on trustworthy synchronized clocks. Define and
  monitor bounded clock skew; fail closed when time is unreliable.
- Verification occurs before execution. Prevent time-of-check/time-of-use races
  with immutable snapshots, conditional backend revisions, transactions, and
  downstream authorization immediately before effects.
- Key compromise can enable forged history until revocation is distributed.
  Rotate, revoke, quarantine affected workflows, preserve evidence, and rebuild
  from an independently trusted source.
- Completed external effects cannot be undone by detecting a bad restore. Use
  idempotency keys, transactions, compensation, reconciliation, and human review
  for irreversible actions.

These APIs provide verifiable application continuity; they do not make the
storage service append-only, replace a database transaction log, or certify the
agent system as compliant.
