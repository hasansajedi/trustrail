"""Bypass corpus for OWASP AISVS C5 step-up and JIT privileges."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    AuthenticationAssurance,
    BackendAuthorizationDecision,
    MemoryPrivilegeGrantStateStore,
    PrivilegedAccessCode,
    PrivilegedAccessManager,
    PrivilegedAccessPolicy,
    PrivilegedActionRequest,
    PrivilegedActorContext,
    PrivilegedAIOperation,
    PrivilegedApprovalEvidence,
    PrivilegedIdentitySnapshot,
    PrivilegedOperationPolicy,
    PrivilegedRiskSnapshot,
    StaticPrivilegedApprovalVerifier,
    StaticStepUpEvidenceVerifier,
    StepUpAuthenticationEvidence,
    privileged_access_reference,
)

NOW = datetime(2026, 9, 27, 16, tzinfo=UTC)
CASES = json.loads(
    (Path(__file__).parent.parent / "security_corpus" / "privileged_ai_access.json").read_text()
)


class MutableIdentity:
    def __init__(self) -> None:
        self.fail = False
        self.snapshot = PrivilegedIdentitySnapshot(
            actor_id="private-operator",
            tenant_id="private-tenant",
            session_id="private-session",
            identity_version="identity-v1",
            role_version="roles-v1",
            role_ids=frozenset({"platform-security"}),
            active=True,
            session_started_at=NOW - timedelta(minutes=5),
            session_expires_at=NOW + timedelta(minutes=5),
        )

    def get_identity(self, actor_id, tenant_id, session_id, now):
        if self.fail:
            raise RuntimeError("unavailable")
        return self.snapshot


class MutableRisk:
    def __init__(self) -> None:
        self.fail = False
        self.snapshot = PrivilegedRiskSnapshot(
            actor_id="private-operator",
            tenant_id="private-tenant",
            session_id="private-session",
            risk_version="risk-v1",
            score=5,
            assessed_at=NOW - timedelta(seconds=5),
            expires_at=NOW + timedelta(minutes=3),
        )

    def get_risk(self, actor_id, tenant_id, session_id, now):
        if self.fail:
            raise RuntimeError("unavailable")
        return self.snapshot


class MutableBackend:
    def __init__(self) -> None:
        self.fail = False
        self.allowed = True

    def authorize(self, request, identity, now):
        if self.fail:
            raise RuntimeError("unavailable")
        return BackendAuthorizationDecision(
            request_digest=request.request_digest,
            allowed=self.allowed,
            authorization_revision="private-backend-revision",
            reason_code="allow" if self.allowed else "deny",
            expires_at=now + timedelta(minutes=1),
        )


class MutableStore(MemoryPrivilegeGrantStateStore):
    fail_consume = False

    def consume(self, grant_id, grant_digest, now):
        if self.fail_consume:
            raise RuntimeError("unavailable")
        return super().consume(grant_id, grant_digest, now)


class UnavailableStepUpVerifier:
    def verify_step_up(self, evidence):
        raise RuntimeError("unavailable")


class UnavailableApprovalVerifier:
    def verify_approval(self, evidence):
        raise RuntimeError("unavailable")


def _policy(version: int = 1) -> PrivilegedAccessPolicy:
    return PrivilegedAccessPolicy(
        policy_id="private-policy",
        version=version,
        operations=(
            PrivilegedOperationPolicy(
                operation=PrivilegedAIOperation.SAFETY_POLICY_MODIFY,
                required_scopes=frozenset({"safety:policy:write"}),
                eligible_role_ids=frozenset({"platform-security"}),
                minimum_assurance=AuthenticationAssurance.PHISHING_RESISTANT,
                allowed_approver_ids=frozenset({"private-reviewer"}),
                maximum_session_duration_seconds=900,
                maximum_step_up_age_seconds=120,
                maximum_grant_ttl_seconds=60,
                maximum_risk_score=20,
            ),
        ),
    )


def _fixture():
    policy = _policy()
    request = PrivilegedActionRequest(
        request_id="private-request",
        actor=PrivilegedActorContext(
            actor_id="private-operator",
            tenant_id="private-tenant",
            session_id="private-session",
            identity_version="identity-v1",
            role_version="roles-v1",
            risk_version="risk-v1",
        ),
        operation=PrivilegedAIOperation.SAFETY_POLICY_MODIFY,
        target_id="private-production-safety-policy",
        purpose_id="private-approved-change",
        requested_scopes=frozenset({"safety:policy:write"}),
        policy_id=policy.policy_id,
        policy_version=policy.version,
        policy_digest=policy.policy_digest,
        nonce="private-nonce",
    )
    step_up = StepUpAuthenticationEvidence(
        evidence_id="private-step-up",
        request_digest=request.request_digest,
        actor_id=request.actor.actor_id,
        tenant_id=request.actor.tenant_id,
        session_id=request.actor.session_id,
        policy_digest=policy.policy_digest,
        nonce=request.nonce,
        assurance=AuthenticationAssurance.PHISHING_RESISTANT,
        authentication_methods=frozenset({"webauthn"}),
        authenticated_at=NOW - timedelta(seconds=5),
        expires_at=NOW + timedelta(minutes=2),
    )
    approval = PrivilegedApprovalEvidence(
        approval_id="private-approval",
        request_digest=request.request_digest,
        actor_id=request.actor.actor_id,
        tenant_id=request.actor.tenant_id,
        approver_id="private-reviewer",
        policy_digest=policy.policy_digest,
        nonce=request.nonce,
        approved_at=NOW - timedelta(seconds=3),
        expires_at=NOW + timedelta(minutes=2),
    )
    return policy, request, step_up, approval


def _manager(policy, step_up, approval, identity, risk, backend, store):
    return PrivilegedAccessManager(
        policy,
        identity_provider=identity,
        risk_provider=risk,
        backend_authorizer=backend,
        step_up_verifier=StaticStepUpEvidenceVerifier(
            frozenset({(step_up.evidence_id, step_up.evidence_digest)})
        ),
        approval_verifier=StaticPrivilegedApprovalVerifier(
            frozenset({(approval.approval_id, approval.approval_digest)})
        ),
        state_store=store,
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_privileged_access_bypass_corpus_fails_closed_without_raw_identifiers(case):
    policy, request, step_up, approval = _fixture()
    identity = MutableIdentity()
    risk = MutableRisk()
    backend = MutableBackend()
    store = MutableStore()
    manager = _manager(policy, step_up, approval, identity, risk, backend, store)
    mutation = case["mutation"]

    if mutation in {"step_up_outage", "approval_outage"}:
        manager = PrivilegedAccessManager(
            policy,
            identity_provider=identity,
            risk_provider=risk,
            backend_authorizer=backend,
            step_up_verifier=(
                UnavailableStepUpVerifier()
                if mutation == "step_up_outage"
                else StaticStepUpEvidenceVerifier(
                    frozenset({(step_up.evidence_id, step_up.evidence_digest)})
                )
            ),
            approval_verifier=(
                UnavailableApprovalVerifier()
                if mutation == "approval_outage"
                else StaticPrivilegedApprovalVerifier(
                    frozenset({(approval.approval_id, approval.approval_digest)})
                )
            ),
            state_store=store,
        )

    if case["phase"] == "issue":
        supplied_step_up = step_up
        supplied_approval = approval
        if mutation == "missing_step_up":
            supplied_step_up = None
        elif mutation == "step_up_actor":
            supplied_step_up = step_up.model_copy(update={"actor_id": "private-attacker"})
        elif mutation == "step_up_tenant":
            supplied_step_up = step_up.model_copy(update={"tenant_id": "private-other-tenant"})
        elif mutation == "step_up_session":
            supplied_step_up = step_up.model_copy(update={"session_id": "private-other-session"})
        elif mutation == "step_up_nonce":
            supplied_step_up = step_up.model_copy(update={"nonce": "private-old-nonce"})
        elif mutation == "weak_assurance":
            supplied_step_up = step_up.model_copy(
                update={"assurance": AuthenticationAssurance.MULTI_FACTOR}
            )
        elif mutation == "stale_step_up":
            supplied_step_up = step_up.model_copy(
                update={
                    "authenticated_at": NOW - timedelta(minutes=3),
                    "expires_at": NOW + timedelta(minutes=1),
                }
            )
        elif mutation == "unverified_step_up":
            supplied_step_up = step_up.model_copy(update={"evidence_id": "private-forged"})
        elif mutation == "missing_approval":
            supplied_approval = None
        elif mutation == "self_approval":
            supplied_approval = approval.model_copy(update={"approver_id": request.actor.actor_id})
        elif mutation == "role_denied":
            identity.snapshot = identity.snapshot.model_copy(
                update={"role_ids": frozenset({"billing"})}
            )
        elif mutation == "long_session":
            identity.snapshot = identity.snapshot.model_copy(
                update={"session_started_at": NOW - timedelta(minutes=20)}
            )
        elif mutation == "risk_denied":
            risk.snapshot = risk.snapshot.model_copy(update={"score": 90})
        elif mutation == "backend_denied":
            backend.allowed = False
        elif mutation == "identity_outage":
            identity.fail = True
        elif mutation == "risk_outage":
            risk.fail = True
        elif mutation == "backend_outage":
            backend.fail = True
        result = manager.issue_grant(
            request,
            step_up=supplied_step_up,
            approval=supplied_approval,
            now=NOW,
        )
    else:
        grant = manager.require_grant(request, step_up=step_up, approval=approval, now=NOW)
        execution_request = request
        if mutation == "target_swap":
            execution_request = request.model_copy(update={"target_id": "private-attacker-target"})
        elif mutation == "grant_forged":
            grant = grant.model_copy(
                update={"target_ref": privileged_access_reference("private-attacker-target")}
            )
        elif mutation == "grant_replay":
            assert manager.authorize_execution(request, grant, now=NOW).is_allowed
        elif mutation == "role_change":
            identity.snapshot = identity.snapshot.model_copy(update={"role_version": "roles-v2"})
        elif mutation == "risk_change":
            risk.snapshot = risk.snapshot.model_copy(update={"risk_version": "risk-v2"})
        elif mutation == "session_change":
            identity.snapshot = identity.snapshot.model_copy(
                update={"session_id": "private-new-session"}
            )
        elif mutation == "policy_change":
            manager = _manager(
                _policy(version=2), step_up, approval, identity, risk, backend, store
            )
        elif mutation == "session_revoke":
            assert manager.revoke_session(request.actor.session_id) == 1
        elif mutation == "backend_change":
            backend.allowed = False
        elif mutation == "state_outage":
            store.fail_consume = True
        result = manager.authorize_execution(execution_request, grant, now=NOW)

    assert not result.is_allowed
    assert PrivilegedAccessCode(case["expected_code"]) in {item.code for item in result.findings}
    serialized = result.model_dump_json()
    assert "private-operator" not in serialized
    assert "private-tenant" not in serialized
    assert "private-production" not in serialized
    assert "private-attacker" not in serialized
