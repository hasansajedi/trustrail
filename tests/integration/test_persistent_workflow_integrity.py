"""End-to-end persistent workflow verification across restart and key rotation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from trustrail import (
    MemoryWorkflowResumeStateStore,
    MemoryWorkflowRevocationProvider,
    PersistedWorkflowState,
    PersistentWorkflowVerifier,
    StaticWorkflowResumeAuthorizer,
    WorkflowBudgetState,
    WorkflowCheckpointSigner,
    WorkflowExecutionEventKind,
    WorkflowIntegrityCode,
    WorkflowIntegrityPolicy,
    WorkflowPolicyVersion,
    WorkflowResumeContext,
    workflow_digest,
)

NOW = datetime(2026, 10, 4, 15, tzinfo=UTC)
GOAL = workflow_digest({"goal": "reconcile authorized records"})
PLAN = workflow_digest({"plan": ["read", "compare", "record"]})
AUTH = workflow_digest({"authorization": "revision-11"})
ACTION = workflow_digest({"action": "read-records"})


def _policy() -> WorkflowIntegrityPolicy:
    return WorkflowIntegrityPolicy(
        policy_id="workflow-continuity",
        version=1,
        trusted_authority_ids=frozenset({"workflow-authority"}),
        maximum_checkpoint_ttl_seconds=600,
        maximum_checkpoint_age_seconds=300,
        maximum_chain_entries=100,
    )


def _context(checkpoint) -> WorkflowResumeContext:
    return WorkflowResumeContext(
        workflow_id=checkpoint.workflow_id,
        tenant_id=checkpoint.tenant_id,
        agent_id=checkpoint.agent_id,
        session_id=checkpoint.session_id,
        goal_digest=checkpoint.goal_digest,
        plan_digest=checkpoint.plan_digest,
        policy_versions=checkpoint.policy_versions,
        resume_authorization_digest=checkpoint.resume_authorization_digest,
        expected_checkpoint_sequence=checkpoint.checkpoint_sequence,
        expected_checkpoint_digest=checkpoint.checkpoint_digest,
        expected_prior_checkpoint_digest=checkpoint.prior_checkpoint_digest,
        expected_chain_id=checkpoint.chain_id,
        expected_chain_length=checkpoint.execution_chain_length,
        expected_chain_head_digest=checkpoint.execution_chain_head_digest,
        budget_limits={item.budget_id: item.limit for item in checkpoint.budgets},
    )


def _verifier(keys, checkpoint, context, store):
    return PersistentWorkflowVerifier(
        _policy(),
        keys,
        authorizer=StaticWorkflowResumeAuthorizer(
            frozenset({(checkpoint.checkpoint_digest, AUTH)})
        ),
        revocation_provider=MemoryWorkflowRevocationProvider(),
        state_store=store,
    )


def test_serialized_restart_continues_exact_chain_across_key_rotation():
    old_signer = WorkflowCheckpointSigner.generate(authority_id="workflow-authority")
    new_signer = WorkflowCheckpointSigner.generate(authority_id="workflow-authority")
    policy_versions = (
        WorkflowPolicyVersion(
            policy_id="record-access",
            version=11,
            policy_digest="a" * 64,
        ),
    )
    budgets = (WorkflowBudgetState(budget_id="tool-calls", limit=5, consumed=1),)
    first = old_signer.sign_entry(
        chain_id="reconcile-chain",
        entry_id="read-authorized",
        event_kind=WorkflowExecutionEventKind.ACTION_AUTHORIZED,
        workflow_id="reconcile-workflow",
        tenant_id="private-tenant",
        agent_id="reconcile-agent",
        session_id="private-session",
        goal_digest=GOAL,
        plan_digest=PLAN,
        action_digest=ACTION,
        authorization_digest=AUTH,
        occurred_at=NOW - timedelta(seconds=2),
    )
    checkpoint_zero = old_signer.sign_checkpoint(
        checkpoint_id="checkpoint-zero",
        workflow_id="reconcile-workflow",
        tenant_id="private-tenant",
        agent_id="reconcile-agent",
        session_id="private-session",
        goal_digest=GOAL,
        plan_digest=PLAN,
        budgets=budgets,
        policy_versions=policy_versions,
        pending_actions=(),
        pending_approvals=(),
        resume_authorization_digest=AUTH,
        chain_id="reconcile-chain",
        execution_chain=(first,),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    serialized = PersistedWorkflowState(
        checkpoint=checkpoint_zero,
        execution_chain=(first,),
    ).model_dump_json()
    restored = PersistedWorkflowState.model_validate_json(serialized)
    context_zero = _context(restored.checkpoint)
    shared_store = MemoryWorkflowResumeStateStore()
    verifier_zero = _verifier(
        (old_signer.trusted_key,), restored.checkpoint, context_zero, shared_store
    )

    assert verifier_zero.require_resume(restored, context_zero, now=NOW).chain_length == 1

    second = new_signer.sign_entry(
        chain_id="reconcile-chain",
        entry_id="read-completed",
        event_kind=WorkflowExecutionEventKind.ACTION_COMPLETED,
        workflow_id="reconcile-workflow",
        tenant_id="private-tenant",
        agent_id="reconcile-agent",
        session_id="private-session",
        goal_digest=GOAL,
        plan_digest=PLAN,
        action_digest=ACTION,
        outcome_digest=workflow_digest({"result": "success"}),
        occurred_at=NOW + timedelta(seconds=1),
        prior_entry=first,
    )
    checkpoint_one = new_signer.sign_checkpoint(
        checkpoint_id="checkpoint-one",
        workflow_id="reconcile-workflow",
        tenant_id="private-tenant",
        agent_id="reconcile-agent",
        session_id="private-session",
        goal_digest=GOAL,
        plan_digest=PLAN,
        budgets=(WorkflowBudgetState(budget_id="tool-calls", limit=5, consumed=2),),
        policy_versions=policy_versions,
        pending_actions=(),
        pending_approvals=(),
        resume_authorization_digest=AUTH,
        chain_id="reconcile-chain",
        execution_chain=(first, second),
        issued_at=NOW + timedelta(seconds=2),
        expires_at=NOW + timedelta(minutes=5),
        prior_checkpoint=checkpoint_zero,
    )
    state_one = PersistedWorkflowState(
        checkpoint=checkpoint_one,
        execution_chain=(first, second),
    )
    context_one = _context(checkpoint_one)
    verifier_one = _verifier(
        (old_signer.trusted_key, new_signer.trusted_key),
        checkpoint_one,
        context_one,
        shared_store,
    )

    resumed = verifier_one.verify_resume(
        PersistedWorkflowState.model_validate_json(state_one.model_dump_json()),
        context_one,
        now=NOW + timedelta(seconds=2),
    )
    partial_restore = state_one.model_copy(update={"execution_chain": (first,)})
    partial = _verifier(
        (old_signer.trusted_key, new_signer.trusted_key),
        checkpoint_one,
        context_one,
        MemoryWorkflowResumeStateStore(),
    ).verify_resume(partial_restore, context_one, now=NOW + timedelta(seconds=2))

    assert resumed.is_authorized
    assert WorkflowIntegrityCode.EXECUTION_DELETION in {item.code for item in partial.findings}
