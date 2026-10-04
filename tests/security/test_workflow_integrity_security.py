"""Bypass corpus for OWASP AISVS C9 persistent workflow integrity."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    MemoryWorkflowResumeStateStore,
    MemoryWorkflowRevocationProvider,
    PersistedWorkflowState,
    PersistentWorkflowVerifier,
    StaticWorkflowResumeAuthorizer,
    WorkflowCheckpointSigner,
    WorkflowExecutionEventKind,
    WorkflowIntegrityPolicy,
    WorkflowPolicyVersion,
    WorkflowResumeContext,
    workflow_digest,
)

NOW = datetime(2026, 10, 4, 17, tzinfo=UTC)
GOAL = workflow_digest({"private_goal": "approved operation"})
PLAN = workflow_digest({"private_plan": ["step-one", "step-two"]})
AUTH = workflow_digest({"private_authorization": "revision-3"})
ACTION = workflow_digest({"private_action": "perform-step"})
CASES = json.loads(
    (Path(__file__).parent.parent / "security_corpus" / "workflow_integrity.json").read_text()
)


def _fixture(*, issued_at=NOW, expires_at=NOW + timedelta(minutes=5)):
    signer = WorkflowCheckpointSigner.generate(authority_id="workflow-authority")
    first = signer.sign_entry(
        chain_id="private-chain",
        entry_id="private-entry-zero",
        event_kind=WorkflowExecutionEventKind.PLAN_ACCEPTED,
        workflow_id="private-workflow",
        tenant_id="private-tenant",
        agent_id="private-agent",
        session_id="private-session",
        goal_digest=GOAL,
        plan_digest=PLAN,
        occurred_at=issued_at - timedelta(seconds=2),
    )
    second = signer.sign_entry(
        chain_id="private-chain",
        entry_id="private-entry-one",
        event_kind=WorkflowExecutionEventKind.ACTION_AUTHORIZED,
        workflow_id="private-workflow",
        tenant_id="private-tenant",
        agent_id="private-agent",
        session_id="private-session",
        goal_digest=GOAL,
        plan_digest=PLAN,
        action_digest=ACTION,
        authorization_digest=AUTH,
        occurred_at=issued_at - timedelta(seconds=1),
        prior_entry=first,
    )
    policies = (
        WorkflowPolicyVersion(
            policy_id="private-policy",
            version=3,
            policy_digest="3" * 64,
        ),
    )
    checkpoint = signer.sign_checkpoint(
        checkpoint_id="private-checkpoint",
        workflow_id="private-workflow",
        tenant_id="private-tenant",
        agent_id="private-agent",
        session_id="private-session",
        goal_digest=GOAL,
        plan_digest=PLAN,
        budgets=(),
        policy_versions=policies,
        pending_actions=(),
        pending_approvals=(),
        resume_authorization_digest=AUTH,
        chain_id="private-chain",
        execution_chain=(first, second),
        issued_at=issued_at,
        expires_at=expires_at,
    )
    state = PersistedWorkflowState(
        checkpoint=checkpoint,
        execution_chain=(first, second),
    )
    context = WorkflowResumeContext(
        workflow_id=checkpoint.workflow_id,
        tenant_id=checkpoint.tenant_id,
        agent_id=checkpoint.agent_id,
        session_id=checkpoint.session_id,
        goal_digest=checkpoint.goal_digest,
        plan_digest=checkpoint.plan_digest,
        policy_versions=checkpoint.policy_versions,
        resume_authorization_digest=AUTH,
        expected_checkpoint_sequence=0,
        expected_checkpoint_digest=checkpoint.checkpoint_digest,
        expected_chain_id=checkpoint.chain_id,
        expected_chain_length=2,
        expected_chain_head_digest=second.entry_digest,
    )
    return signer, state, context


def _verifier(signer, state, context, *, accepted=True, key=None, revocations=None, store=None):
    accepted_pairs = (
        frozenset({(state.checkpoint.checkpoint_digest, context.resume_authorization_digest)})
        if accepted
        else frozenset()
    )
    return PersistentWorkflowVerifier(
        WorkflowIntegrityPolicy(
            policy_id="workflow-security-policy",
            version=1,
            trusted_authority_ids=frozenset({"workflow-authority"}),
            maximum_checkpoint_ttl_seconds=600,
            maximum_checkpoint_age_seconds=300,
            maximum_chain_entries=100,
        ),
        (key or signer.trusted_key,),
        authorizer=StaticWorkflowResumeAuthorizer(accepted_pairs),
        revocation_provider=revocations or MemoryWorkflowRevocationProvider(),
        state_store=store,
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_persistent_workflow_bypass_corpus(case):
    signer, state, context = _fixture()
    mutation = case["mutation"]
    accepted = True
    key = signer.trusted_key
    revocations = MemoryWorkflowRevocationProvider()
    store = MemoryWorkflowResumeStateStore()

    if mutation == "unsigned_checkpoint":
        state = state.model_copy(
            update={"checkpoint": state.checkpoint.model_copy(update={"signature": None})}
        )
    elif mutation == "checkpoint_signature":
        state = state.model_copy(
            update={"checkpoint": state.checkpoint.model_copy(update={"plan_digest": "f" * 64})}
        )
    elif mutation == "unknown_key":
        state = state.model_copy(
            update={
                "checkpoint": state.checkpoint.model_copy(update={"key_id": "sha256:" + "f" * 64})
            }
        )
    elif mutation == "revoked_key":
        key = key.model_copy(update={"revoked": True})
    elif mutation == "expired":
        signer, state, context = _fixture(
            issued_at=NOW - timedelta(minutes=6),
            expires_at=NOW - timedelta(seconds=1),
        )
        key = signer.trusted_key
    elif mutation == "session":
        context = context.model_copy(update={"session_id": "attacker-session"})
    elif mutation == "plan":
        context = context.model_copy(update={"plan_digest": "e" * 64})
    elif mutation == "policy":
        changed = context.policy_versions[0].model_copy(update={"version": 2})
        context = context.model_copy(update={"policy_versions": (changed,)})
    elif mutation == "deletion":
        state = state.model_copy(update={"execution_chain": state.execution_chain[:-1]})
    elif mutation == "insertion":
        extra = signer.sign_entry(
            chain_id="private-chain",
            entry_id="inserted-entry",
            event_kind=WorkflowExecutionEventKind.ACTION_STARTED,
            workflow_id="private-workflow",
            tenant_id="private-tenant",
            agent_id="private-agent",
            session_id="private-session",
            goal_digest=GOAL,
            plan_digest=PLAN,
            action_digest=ACTION,
            occurred_at=NOW,
            prior_entry=state.execution_chain[-1],
        )
        state = state.model_copy(update={"execution_chain": (*state.execution_chain, extra)})
    elif mutation == "reordering":
        state = state.model_copy(update={"execution_chain": state.execution_chain[::-1]})
    elif mutation == "entry_signature":
        forged = state.execution_chain[0].model_copy(update={"entry_id": "forged-entry"})
        state = state.model_copy(update={"execution_chain": (forged, state.execution_chain[1])})
    elif mutation == "rollback":
        context = context.model_copy(
            update={
                "expected_checkpoint_sequence": 1,
                "expected_checkpoint_digest": "d" * 64,
            }
        )
    elif mutation == "prior":
        context = context.model_copy(update={"expected_prior_checkpoint_digest": "c" * 64})
    elif mutation == "authorization":
        accepted = False
    elif mutation == "revocation":
        revocations.revoke_workflow(state.checkpoint.workflow_id)
    elif mutation == "replay":
        verifier = _verifier(
            signer,
            state,
            context,
            key=key,
            revocations=revocations,
            store=store,
        )
        assert verifier.verify_resume(state, context, now=NOW).is_authorized
        result = verifier.verify_resume(state, context, now=NOW)
        assert result.findings[0].code.value == case["expected_code"]
        return
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    result = _verifier(
        signer,
        state,
        context,
        accepted=accepted,
        key=key,
        revocations=revocations,
        store=store,
    ).verify_resume(state, context, now=NOW)

    assert case["expected_code"] in {item.code.value for item in result.findings}


def test_verification_evidence_excludes_prompts_credentials_and_raw_identity():
    signer, state, context = _fixture()
    decision = _verifier(signer, state, context).verify_resume(state, context, now=NOW)
    serialized = decision.model_dump_json()

    assert decision.is_authorized
    assert "approved operation" not in serialized
    assert "step-one" not in serialized
    assert "private_authorization" not in serialized
