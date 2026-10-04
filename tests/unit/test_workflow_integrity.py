"""Unit tests for signed persistent workflow continuity."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from trustrail import (
    GuardAction,
    MemoryWorkflowIntegrityAuditSink,
    MemoryWorkflowRevocationProvider,
    PendingActionBinding,
    PendingActionStatus,
    PendingApprovalBinding,
    PersistedWorkflowState,
    PersistentWorkflowVerifier,
    StaticWorkflowResumeAuthorizer,
    WorkflowBudgetState,
    WorkflowCheckpointSigner,
    WorkflowExecutionEventKind,
    WorkflowIntegrityCode,
    WorkflowIntegrityError,
    WorkflowIntegrityPolicy,
    WorkflowPolicyVersion,
    WorkflowResumeContext,
    canonical_workflow_json,
    workflow_digest,
)

NOW = datetime(2026, 10, 4, 12, tzinfo=UTC)
GOAL = workflow_digest({"goal": "prepare approved incident report"})
PLAN = workflow_digest({"steps": ["collect", "review", "publish"]})
AUTHORIZATION = workflow_digest({"authorization": "current-revision-7"})
ACTION = workflow_digest({"action": "collect", "resource": "case-42"})
APPROVAL = workflow_digest({"approval": "security-review-42"})


def _policy(**updates) -> WorkflowIntegrityPolicy:
    values = {
        "policy_id": "persistent-workflow-policy",
        "version": 3,
        "trusted_authority_ids": frozenset({"workflow-control-plane"}),
        "maximum_checkpoint_ttl_seconds": 600,
        "maximum_checkpoint_age_seconds": 300,
        "clock_skew_seconds": 5,
        "maximum_chain_entries": 100,
        "maximum_pending_actions": 10,
        "maximum_pending_approvals": 10,
        "resume_permit_ttl_seconds": 30,
    }
    values.update(updates)
    return WorkflowIntegrityPolicy(**values)  # type: ignore[arg-type]


def _signed_state(
    *,
    signer: WorkflowCheckpointSigner | None = None,
    prior_checkpoint=None,
    issued_at: datetime = NOW,
    expires_at: datetime = NOW + timedelta(minutes=5),
    pending_expires_at: datetime = NOW + timedelta(minutes=2),
):
    signer = signer or WorkflowCheckpointSigner.generate(authority_id="workflow-control-plane")
    first = signer.sign_entry(
        chain_id="execution-chain-42",
        entry_id="entry-0",
        event_kind=WorkflowExecutionEventKind.PLAN_ACCEPTED,
        workflow_id="workflow-42",
        tenant_id="tenant-private",
        agent_id="report-agent",
        session_id="session-private",
        goal_digest=GOAL,
        plan_digest=PLAN,
        occurred_at=issued_at - timedelta(seconds=3),
    )
    second = signer.sign_entry(
        chain_id="execution-chain-42",
        entry_id="entry-1",
        event_kind=WorkflowExecutionEventKind.ACTION_AUTHORIZED,
        workflow_id="workflow-42",
        tenant_id="tenant-private",
        agent_id="report-agent",
        session_id="session-private",
        goal_digest=GOAL,
        plan_digest=PLAN,
        action_digest=ACTION,
        authorization_digest=AUTHORIZATION,
        occurred_at=issued_at - timedelta(seconds=2),
        prior_entry=first,
    )
    policies = (
        WorkflowPolicyVersion(
            policy_id="agent-actions",
            version=7,
            policy_digest="1" * 64,
        ),
        WorkflowPolicyVersion(
            policy_id="data-handling",
            version=4,
            policy_digest="2" * 64,
        ),
    )
    budgets = (
        WorkflowBudgetState(budget_id="tool-calls", limit=10, consumed=2, reserved=1),
        WorkflowBudgetState(budget_id="tokens", limit=20_000, consumed=3_000),
    )
    pending_actions = (
        PendingActionBinding(
            action_id="publish-report",
            action_digest=ACTION,
            authorization_digest=AUTHORIZATION,
            status=PendingActionStatus.AWAITING_APPROVAL,
            created_at=issued_at - timedelta(seconds=1),
            expires_at=pending_expires_at,
        ),
    )
    pending_approvals = (
        PendingApprovalBinding(
            approval_id="approval-42",
            action_id="publish-report",
            action_digest=ACTION,
            approval_request_digest=APPROVAL,
            requested_at=issued_at - timedelta(seconds=1),
            expires_at=pending_expires_at,
        ),
    )
    chain = (first, second)
    checkpoint = signer.sign_checkpoint(
        checkpoint_id=f"checkpoint-{0 if prior_checkpoint is None else 1}",
        workflow_id="workflow-42",
        tenant_id="tenant-private",
        agent_id="report-agent",
        session_id="session-private",
        goal_digest=GOAL,
        plan_digest=PLAN,
        budgets=budgets,
        policy_versions=policies,
        pending_actions=pending_actions,
        pending_approvals=pending_approvals,
        resume_authorization_digest=AUTHORIZATION,
        chain_id="execution-chain-42",
        execution_chain=chain,
        issued_at=issued_at,
        expires_at=expires_at,
        prior_checkpoint=prior_checkpoint,
    )
    state = PersistedWorkflowState(checkpoint=checkpoint, execution_chain=chain)
    context = WorkflowResumeContext(
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
    return signer, state, context


def _verifier(
    signer,
    state,
    context,
    *,
    store=None,
    revocations=None,
    audit=None,
    accepted=True,
    trusted_keys=None,
):
    accepted_set = (
        frozenset(
            {
                (
                    state.checkpoint.checkpoint_digest,
                    context.resume_authorization_digest,
                )
            }
        )
        if accepted
        else frozenset()
    )
    return PersistentWorkflowVerifier(
        _policy(),
        trusted_keys or (signer.trusted_key,),
        authorizer=StaticWorkflowResumeAuthorizer(accepted_set),
        revocation_provider=revocations or MemoryWorkflowRevocationProvider(),
        state_store=store,
        audit_sink=audit,
    )


def test_signed_checkpoint_resumes_once_with_content_free_evidence():
    signer, state, context = _signed_state()
    audit = MemoryWorkflowIntegrityAuditSink()
    verifier = _verifier(signer, state, context, audit=audit)

    permit = verifier.require_resume(state, context, now=NOW)
    replay = verifier.verify_resume(state, context, now=NOW)

    assert permit.checkpoint_digest == state.checkpoint.checkpoint_digest
    assert permit.expires_at == NOW + timedelta(seconds=30)
    assert replay.findings[0].code == WorkflowIntegrityCode.RESUME_REPLAYED
    serialized = "".join(event.model_dump_json() for event in audit.events)
    for private_value in (
        "workflow-42",
        "tenant-private",
        "report-agent",
        "session-private",
    ):
        assert private_value not in serialized


def test_checkpoint_signature_detects_state_tampering():
    signer, state, context = _signed_state()
    tampered_checkpoint = state.checkpoint.model_copy(update={"plan_digest": "f" * 64})
    tampered = state.model_copy(update={"checkpoint": tampered_checkpoint})
    matching_context = context.model_copy(update={"plan_digest": "f" * 64})
    verifier = _verifier(signer, tampered, matching_context)

    result = verifier.verify_resume(tampered, matching_context, now=NOW)

    assert result.findings[0].code == WorkflowIntegrityCode.CHECKPOINT_SIGNATURE_INVALID


@pytest.mark.parametrize(
    "context_update",
    [
        {"tenant_id": "tenant-attacker"},
        {"agent_id": "other-agent"},
        {"session_id": "other-session"},
        {"goal_digest": "a" * 64},
        {"plan_digest": "b" * 64},
        {"resume_authorization_digest": "c" * 64},
    ],
)
def test_trusted_resume_context_rejects_cross_context_substitution(context_update):
    signer, state, context = _signed_state()
    rebound = context.model_copy(update=context_update)
    verifier = _verifier(signer, state, rebound)

    result = verifier.verify_resume(state, rebound, now=NOW)

    assert WorkflowIntegrityCode.CHECKPOINT_CONTEXT_MISMATCH in {
        item.code for item in result.findings
    }


def test_chain_detects_deletion_insertion_reordering_and_signature_tampering():
    signer, state, context = _signed_state()

    deleted = state.model_copy(update={"execution_chain": state.execution_chain[:-1]})
    deletion = _verifier(signer, deleted, context).verify_resume(deleted, context, now=NOW)

    extra = signer.sign_entry(
        chain_id="execution-chain-42",
        entry_id="entry-2",
        event_kind=WorkflowExecutionEventKind.ACTION_STARTED,
        workflow_id="workflow-42",
        tenant_id="tenant-private",
        agent_id="report-agent",
        session_id="session-private",
        goal_digest=GOAL,
        plan_digest=PLAN,
        action_digest=ACTION,
        occurred_at=NOW,
        prior_entry=state.execution_chain[-1],
    )
    inserted = state.model_copy(update={"execution_chain": (*state.execution_chain, extra)})
    insertion = _verifier(signer, inserted, context).verify_resume(inserted, context, now=NOW)

    reordered = state.model_copy(update={"execution_chain": state.execution_chain[::-1]})
    reordering = _verifier(signer, reordered, context).verify_resume(reordered, context, now=NOW)

    forged_entry = state.execution_chain[0].model_copy(update={"entry_id": "forged-entry"})
    forged = state.model_copy(update={"execution_chain": (forged_entry, state.execution_chain[1])})
    forgery = _verifier(signer, forged, context).verify_resume(forged, context, now=NOW)

    assert WorkflowIntegrityCode.EXECUTION_DELETION in {x.code for x in deletion.findings}
    assert WorkflowIntegrityCode.EXECUTION_INSERTION in {x.code for x in insertion.findings}
    assert WorkflowIntegrityCode.EXECUTION_REORDERED in {x.code for x in reordering.findings}
    assert WorkflowIntegrityCode.EXECUTION_SIGNATURE_INVALID in {x.code for x in forgery.findings}


def test_trusted_anchor_detects_old_signed_checkpoint_rollback():
    signer, state, context = _signed_state()
    rollback_context = context.model_copy(
        update={
            "expected_checkpoint_sequence": 1,
            "expected_checkpoint_digest": "d" * 64,
            "expected_prior_checkpoint_digest": state.checkpoint.checkpoint_digest,
        }
    )
    verifier = _verifier(signer, state, rollback_context)

    result = verifier.verify_resume(state, rollback_context, now=NOW)

    assert WorkflowIntegrityCode.ROLLBACK_DETECTED in {x.code for x in result.findings}
    assert WorkflowIntegrityCode.PRIOR_STATE_MISMATCH in {x.code for x in result.findings}


def test_expired_checkpoint_pending_approval_and_policy_change_fail_closed():
    signer, expired_state, expired_context = _signed_state(
        issued_at=NOW - timedelta(minutes=10),
        expires_at=NOW - timedelta(minutes=1),
        pending_expires_at=NOW - timedelta(minutes=2),
    )
    result = _verifier(signer, expired_state, expired_context).verify_resume(
        expired_state, expired_context, now=NOW
    )

    assert {
        WorkflowIntegrityCode.CHECKPOINT_EXPIRED,
        WorkflowIntegrityCode.CHECKPOINT_TOO_OLD,
        WorkflowIntegrityCode.PENDING_APPROVAL_EXPIRED,
    }.issubset({item.code for item in result.findings})

    signer, state, context = _signed_state()
    changed_policy = context.policy_versions[0].model_copy(update={"version": 8})
    changed_context = context.model_copy(
        update={"policy_versions": (changed_policy, context.policy_versions[1])}
    )
    policy_result = _verifier(signer, state, changed_context).verify_resume(
        state, changed_context, now=NOW
    )
    assert WorkflowIntegrityCode.POLICY_MISMATCH in {item.code for item in policy_result.findings}


def test_live_authorization_revocation_and_service_failures_are_enforced():
    signer, state, context = _signed_state()
    denied = _verifier(signer, state, context, accepted=False).verify_resume(
        state, context, now=NOW
    )
    assert denied.findings[0].code == WorkflowIntegrityCode.AUTHORIZATION_DENIED

    revocations = MemoryWorkflowRevocationProvider()
    revocations.revoke_checkpoint(state.checkpoint.checkpoint_digest)
    revoked = _verifier(signer, state, context, revocations=revocations).verify_resume(
        state, context, now=NOW
    )
    assert revoked.findings[0].code == WorkflowIntegrityCode.WORKFLOW_REVOKED

    class UnavailableAuthorizer:
        def authorize_resume(self, context, checkpoint, now):
            raise RuntimeError("private backend detail")

    verifier = PersistentWorkflowVerifier(
        _policy(),
        (signer.trusted_key,),
        authorizer=UnavailableAuthorizer(),
        revocation_provider=MemoryWorkflowRevocationProvider(),
    )
    unavailable = verifier.verify_resume(state, context, now=NOW)
    assert unavailable.findings[0].code == WorkflowIntegrityCode.AUTHORIZATION_UNAVAILABLE
    with pytest.raises(WorkflowIntegrityError) as blocked:
        verifier.require_resume(state, context, now=NOW)
    assert "private backend detail" not in str(blocked.value)


def test_key_rotation_verifies_historical_links_and_new_checkpoint():
    old_signer, old_state, _ = _signed_state()
    new_signer = WorkflowCheckpointSigner.generate(authority_id="workflow-control-plane")
    first = old_state.execution_chain[0]
    rotated_entry = new_signer.sign_entry(
        chain_id="execution-chain-42",
        entry_id="entry-1-rotated",
        event_kind=WorkflowExecutionEventKind.ACTION_AUTHORIZED,
        workflow_id="workflow-42",
        tenant_id="tenant-private",
        agent_id="report-agent",
        session_id="session-private",
        goal_digest=GOAL,
        plan_digest=PLAN,
        action_digest=ACTION,
        authorization_digest=AUTHORIZATION,
        occurred_at=NOW - timedelta(seconds=1),
        prior_entry=first,
    )
    checkpoint = new_signer.sign_checkpoint(
        checkpoint_id="checkpoint-rotated",
        workflow_id="workflow-42",
        tenant_id="tenant-private",
        agent_id="report-agent",
        session_id="session-private",
        goal_digest=GOAL,
        plan_digest=PLAN,
        budgets=old_state.checkpoint.budgets,
        policy_versions=old_state.checkpoint.policy_versions,
        pending_actions=old_state.checkpoint.pending_actions,
        pending_approvals=old_state.checkpoint.pending_approvals,
        resume_authorization_digest=AUTHORIZATION,
        chain_id="execution-chain-42",
        execution_chain=(first, rotated_entry),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    state = PersistedWorkflowState(
        checkpoint=checkpoint,
        execution_chain=(first, rotated_entry),
    )
    context = WorkflowResumeContext(
        workflow_id=checkpoint.workflow_id,
        tenant_id=checkpoint.tenant_id,
        agent_id=checkpoint.agent_id,
        session_id=checkpoint.session_id,
        goal_digest=checkpoint.goal_digest,
        plan_digest=checkpoint.plan_digest,
        policy_versions=checkpoint.policy_versions,
        resume_authorization_digest=AUTHORIZATION,
        expected_checkpoint_sequence=0,
        expected_checkpoint_digest=checkpoint.checkpoint_digest,
        expected_chain_id=checkpoint.chain_id,
        expected_chain_length=2,
        expected_chain_head_digest=rotated_entry.entry_digest,
        budget_limits={item.budget_id: item.limit for item in checkpoint.budgets},
    )
    verifier = _verifier(
        new_signer,
        state,
        context,
        trusted_keys=(old_signer.trusted_key, new_signer.trusted_key),
    )

    assert verifier.verify_resume(state, context, now=NOW).is_authorized


def test_atomic_resume_claim_allows_only_one_concurrent_consumer():
    signer, state, context = _signed_state()
    verifier = _verifier(signer, state, context)

    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(
            pool.map(lambda _: verifier.verify_resume(state, context, now=NOW), range(8))
        )

    assert sum(item.action == GuardAction.ALLOW for item in decisions) == 1


def test_canonical_digest_is_stable_and_checkpoint_excludes_workflow_content():
    assert canonical_workflow_json({"b": 2, "a": "e\u0301"}) == canonical_workflow_json(
        {"a": "é", "b": 2}
    )
    signer, state, _ = _signed_state()
    del signer
    serialized = state.model_dump_json()
    assert "prepare approved incident report" not in serialized
    assert "collect" not in serialized
    assert "case-42" not in serialized

    policy_a = _policy(trusted_authority_ids=frozenset({"authority-a", "authority-b"}))
    policy_b = _policy(trusted_authority_ids=frozenset({"authority-b", "authority-a"}))
    assert policy_a.policy_digest == policy_b.policy_digest
