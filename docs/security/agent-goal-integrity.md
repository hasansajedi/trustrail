# Agent goal integrity

trustrail provides a deterministic planning boundary for
[OWASP ASI01:2026 Agent Goal Hijack](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).
It treats model plans, retrieved instructions, memory, tool output, and delegated
agent proposals as untrusted. An application-authored `GoalManifest` remains the
authority for what the execution may pursue.

Content scanning is defense-in-depth. A plan step that looks benign is not
authorized unless it is bound to the current manifest, identity, session,
execution, constraints, action allowlist, sequence, and delegation state.

## Create the authorized goal

Construct the owner, approval context, objective, constraints, actions, and
delegates from authenticated application state—not model output or retrieved
content:

```python
from datetime import UTC, datetime, timedelta

from trustrail import (
    GoalApprovalContext,
    GoalConstraint,
    GoalConstraintKind,
    GoalManifest,
    GoalOwner,
)

now = datetime.now(tz=UTC)
manifest = GoalManifest.create(
    manifest_id="summarize-selected-document",
    execution_id=execution.id,
    session_id=session.id,
    owner=GoalOwner(
        owner_id=authenticated_user.id,
        tenant_id=authenticated_user.tenant_id,
    ),
    primary_actor_id="document-agent",
    objective="Summarize the document explicitly selected by the user",
    constraints=(
        GoalConstraint(
            constraint_id="selected-document-only",
            kind=GoalConstraintKind.BOUNDARY,
            description="Only access the selected document",
        ),
    ),
    allowed_action_ids=frozenset({"documents.read", "summary.write"}),
    allowed_delegate_ids=frozenset({"reader-agent"}),
    approval_context=GoalApprovalContext(
        context_id=user_request.id,
        authorized_by=authenticated_user.id,
        allowed_approver_ids=frozenset({"workflow-reviewer"}),
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
    ),
    issued_at=now,
    expires_at=now + timedelta(minutes=15),
)
```

The goal digest covers the full objective, constraints, allowed actions, and
delegates. The manifest digest additionally binds owner, tenant, actor, session,
execution, approval context, expiry, revision, parent, and original-goal digest.
Objective and constraint text are excluded from normal Pydantic serialization
and representation; their digests remain available for audit correlation.

## Validate every plan step and delegation

Keep one `GoalExecutionState` for the complete execution. Validate immediately
before scheduling, executing, or delegating each step:

```python
from trustrail import (
    GoalInputSource,
    GoalIntegrityGuard,
    GoalPrincipal,
    ProposedPlanStep,
)

goal_guard = GoalIntegrityGuard()
goal_state = goal_guard.new_state(manifest)

proposal = ProposedPlanStep(
    step_id="read-document",
    sequence=1,
    execution_id=manifest.execution_id,
    session_id=manifest.session_id,
    principal=GoalPrincipal(
        actor_id="document-agent",
        owner_id=manifest.owner.owner_id,
        tenant_id=manifest.owner.tenant_id,
    ),
    source=GoalInputSource.AGENT,
    action_id="documents.read",
    description=model_step.description,
    expected_manifest_digest=manifest.manifest_digest,
    constraint_ids=manifest.constraint_ids,
)

authorized_step = goal_guard.require_step(manifest, proposal, goal_state)
execute_action(authorized_step.action_id)
```

`require_step()` returns an immutable snapshot whose description is excluded
from normal serialization. Execute that snapshot, not the original proposal.
Then apply `ToolAuthorizer` immediately before an actual tool call; goal
integrity determines whether a step belongs to the objective, while tool
authorization independently enforces exact capability, arguments, ownership,
scope, approval, and execution budgets.

A delegate cannot submit steps merely because it appears in
`allowed_delegate_ids`. A valid earlier step must explicitly establish that
delegation. Removing a delegate through an approved mutation revokes its active
state.

## Approve material goal changes

Every objective, constraint, action, or delegate change—even a small incremental
change—requires an out-of-band approval bound to the exact mutation digest:

```python
from trustrail import GoalMutationApproval, ProposedGoalMutation

mutation = ProposedGoalMutation(
    mutation_id="include-second-document",
    execution_id=manifest.execution_id,
    session_id=manifest.session_id,
    principal=proposal.principal,
    source=GoalInputSource.AUTHORIZED_USER,
    expected_manifest_digest=manifest.manifest_digest,
    reason="The user selected one additional document",
    proposed_objective="Summarize both user-selected documents",
)

pending = goal_guard.validate_mutation(manifest, mutation, goal_state)
assert pending.requires_approval

approval = GoalMutationApproval(
    approval_id=approval_record.id,
    mutation_digest=mutation.mutation_digest,
    approver_id=approval_record.approver_id,
    expires_at=approval_record.expires_at,
)
updated_manifest = goal_guard.require_mutation(
    manifest,
    mutation.model_copy(update={"approval": approval}),
    goal_state,
)
```

Configure a `GoalApprovalVerifier` that authenticates a server-side record or a
signed grant. Approvals must come from the manifest's allowed reviewer set, are
time-bound, and are consumed once. The new manifest links to its parent and
retains the original goal digest. Old plan steps and old manifests then fail as
stale, preventing gradual or cross-session rebinding.

## Drift and bypass detection

The deterministic bindings reject dropped constraints, undeclared actions,
unknown actors, unestablished delegates, reordered/replayed steps, stale
manifests, and cross-owner, tenant, session, or execution proposals.

Bounded normalization also detects common direct, URL/hex/invisible-Unicode, and
Base64-encoded goal-hijacking instructions. A bounded history joins separately
safe fragments to catch split instructions across multiple plan steps. These
signals block rather than changing the authoritative manifest.

## Content-free audit evidence

Pass a `GoalIntegrityAuditSink` to receive one event for every allow, block, or
approval decision. Events contain operation, decision, manifest/execution/session,
responsible actor, owner, tenant, source class, finding codes, original/current
goal digests, attempted-change digest, and approval ID. They never include the
objective, constraints, step description, mutation reason, or proposed objective.

`MemoryGoalIntegrityAuditSink` is suitable for tests and local development.
Production sinks should write to access-controlled, append-only storage and
apply organizational retention policy.

## Security assumptions, limitations, and residual risk

- The application must construct manifests, identity, source labels, session and
  execution IDs, and approval context from trusted control-plane state. Pydantic
  validation establishes shape and integrity, not the truth of those inputs.
- Complete mediation is required. Every planner, scheduler, delegate, retry,
  resume path, and tool executor must require a current authorized step. A direct
  SDK or queue path can bypass an application-only guard.
- Digest integrity is not authenticity. Protect manifest creation and storage,
  or sign/pin the manifest digest outside the agent's writable state.
- `GoalExecutionState` is mutable, process-local security state. Never expose it
  to a model or delegate, never recreate it to evade limits, and use atomic shared
  state for multi-worker or resumed executions.
- Action IDs must identify narrow capabilities. A broad action such as shell,
  unrestricted HTTP, or generic database access can satisfy a manifest while
  still causing harm. Retain `ToolAuthorizer`, service-side authorization,
  sandboxing, egress control, and transaction/value limits.
- Pattern matching cannot prove semantic alignment and can miss paraphrased,
  multilingual, steganographic, multimodal, or long-horizon drift. Use narrow
  action contracts, independent plan review, behavior monitoring, and
  application-specific red-team corpora.
- Goal and step text remains in application memory even though normal
  serialization omits it. Apply memory isolation, access control, encryption,
  retention limits, and crash-dump/log hygiene.
- Human approval can be mistaken or socially engineered. Present the exact
  owner, old/new goal digests, decoded human-readable change, constraints,
  actions, delegates, and downstream effects through a trusted review channel.

See the runnable
[`goal_integrity.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/goal_integrity.py)
example and [excessive agency](excessive-agency.md) for the downstream tool
boundary.
