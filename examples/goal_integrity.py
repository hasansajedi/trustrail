"""Bind an agent plan to an authorized goal and approve one exact mutation."""

from datetime import UTC, datetime, timedelta

from trustrail import (
    GoalApprovalContext,
    GoalConstraint,
    GoalConstraintKind,
    GoalInputSource,
    GoalIntegrityGuard,
    GoalManifest,
    GoalMutationApproval,
    GoalOwner,
    GoalPrincipal,
    MemoryGoalIntegrityAuditSink,
    ProposedGoalMutation,
    ProposedPlanStep,
    StaticGoalApprovalVerifier,
)

now = datetime.now(tz=UTC)
manifest = GoalManifest.create(
    manifest_id="summarize-selected-document",
    execution_id="execution-123",
    session_id="session-123",
    owner=GoalOwner(owner_id="user-7", tenant_id="tenant-a"),
    primary_actor_id="document-agent",
    objective="Summarize the document selected by user-7",
    constraints=(
        GoalConstraint(
            constraint_id="selected-document-only",
            kind=GoalConstraintKind.BOUNDARY,
            description="Only access the document selected by user-7",
        ),
    ),
    allowed_action_ids=frozenset({"documents.read", "summary.write"}),
    allowed_delegate_ids=frozenset({"reader-agent"}),
    approval_context=GoalApprovalContext(
        context_id="user-request-123",
        authorized_by="user-7",
        allowed_approver_ids=frozenset({"reviewer-1"}),
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
    ),
    issued_at=now,
    expires_at=now + timedelta(minutes=15),
)

audit = MemoryGoalIntegrityAuditSink()
goal_guard = GoalIntegrityGuard(
    approval_verifier=StaticGoalApprovalVerifier(frozenset({"approval-1"})),
    audit_sink=audit,
)
state = goal_guard.new_state(manifest)
principal = GoalPrincipal(
    actor_id="document-agent",
    owner_id="user-7",
    tenant_id="tenant-a",
)

step = ProposedPlanStep(
    step_id="read-selected-document",
    sequence=1,
    execution_id=manifest.execution_id,
    session_id=manifest.session_id,
    principal=principal,
    source=GoalInputSource.AGENT,
    action_id="documents.read",
    description="Read the exact document selected by the user",
    expected_manifest_digest=manifest.manifest_digest,
    constraint_ids=manifest.constraint_ids,
)
authorized_step = goal_guard.require_step(manifest, step, state)
print("Authorized step:", authorized_step.action_id)

mutation = ProposedGoalMutation(
    mutation_id="include-second-document",
    execution_id=manifest.execution_id,
    session_id=manifest.session_id,
    principal=principal,
    source=GoalInputSource.AUTHORIZED_USER,
    expected_manifest_digest=manifest.manifest_digest,
    reason="The user selected one additional document",
    proposed_objective="Summarize both documents selected by user-7",
)
pending = goal_guard.validate_mutation(manifest, mutation, state)
print("Mutation before approval:", pending.action.value)

approval = GoalMutationApproval(
    approval_id="approval-1",
    mutation_digest=mutation.mutation_digest,
    approver_id="reviewer-1",
    expires_at=now + timedelta(minutes=5),
)
updated_manifest = goal_guard.require_mutation(
    manifest,
    mutation.model_copy(update={"approval": approval}),
    state,
)
print("Updated goal revision:", updated_manifest.revision)
print("Content-free audit events:", len(audit.events))
