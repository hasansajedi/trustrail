"""Unit tests for step-up authentication and JIT AI privileges."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from trustrail import (
    AuthenticationAssurance,
    BackendAuthorizationDecision,
    GuardAction,
    MemoryPrivilegedAccessAuditSink,
    MemoryPrivilegeGrantStateStore,
    PrivilegedAccessCode,
    PrivilegedAccessError,
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
)

NOW = datetime(2026, 9, 27, 12, tzinfo=UTC)


class IdentityProvider:
    def __init__(self, snapshot: PrivilegedIdentitySnapshot) -> None:
        self.snapshot = snapshot
        self.calls = 0
        self.fail = False

    def get_identity(self, actor_id, tenant_id, session_id, now):
        self.calls += 1
        if self.fail:
            raise RuntimeError("identity unavailable")
        return self.snapshot


class RiskProvider:
    def __init__(self, snapshot: PrivilegedRiskSnapshot) -> None:
        self.snapshot = snapshot
        self.calls = 0
        self.fail = False

    def get_risk(self, actor_id, tenant_id, session_id, now):
        self.calls += 1
        if self.fail:
            raise RuntimeError("risk unavailable")
        return self.snapshot


class BackendAuthorizer:
    def __init__(self) -> None:
        self.calls = 0
        self.allowed = True
        self.fail = False
        self.revision = "backend-revision-1"

    def authorize(self, request, identity, now):
        self.calls += 1
        if self.fail:
            raise RuntimeError("backend unavailable")
        return BackendAuthorizationDecision(
            request_digest=request.request_digest,
            allowed=self.allowed,
            authorization_revision=self.revision,
            reason_code="policy-allow" if self.allowed else "policy-deny",
            expires_at=now + timedelta(minutes=2),
        )


def _policy(**rule_updates) -> PrivilegedAccessPolicy:
    values = {
        "operation": PrivilegedAIOperation.MODEL_WEIGHT_EXPORT,
        "required_scopes": frozenset({"models:weights:export"}),
        "eligible_role_ids": frozenset({"model-security-admin"}),
        "minimum_assurance": AuthenticationAssurance.PHISHING_RESISTANT,
        "require_independent_approval": True,
        "allowed_approver_ids": frozenset({"security-reviewer"}),
        "maximum_session_duration_seconds": 900,
        "maximum_step_up_age_seconds": 120,
        "maximum_grant_ttl_seconds": 60,
        "maximum_risk_score": 30,
    }
    values.update(rule_updates)
    return PrivilegedAccessPolicy(
        policy_id="privileged-ai-policy",
        version=7,
        operations=(PrivilegedOperationPolicy(**values),),  # type: ignore[arg-type]
    )


def _request(policy: PrivilegedAccessPolicy, **updates) -> PrivilegedActionRequest:
    values = {
        "request_id": "export-request-42",
        "actor": PrivilegedActorContext(
            actor_id="platform-admin",
            tenant_id="tenant-a",
            session_id="session-a",
            identity_version="identity-v1",
            role_version="roles-v1",
            risk_version="risk-v1",
        ),
        "operation": PrivilegedAIOperation.MODEL_WEIGHT_EXPORT,
        "target_id": "private-model-weights-42",
        "purpose_id": "incident-investigation",
        "requested_scopes": frozenset({"models:weights:export"}),
        "policy_id": policy.policy_id,
        "policy_version": policy.version,
        "policy_digest": policy.policy_digest,
        "nonce": "nonce-42",
    }
    values.update(updates)
    return PrivilegedActionRequest(**values)  # type: ignore[arg-type]


def _identity(**updates) -> PrivilegedIdentitySnapshot:
    values = {
        "actor_id": "platform-admin",
        "tenant_id": "tenant-a",
        "session_id": "session-a",
        "identity_version": "identity-v1",
        "role_version": "roles-v1",
        "role_ids": frozenset({"model-security-admin"}),
        "active": True,
        "session_started_at": NOW - timedelta(minutes=5),
        "session_expires_at": NOW + timedelta(minutes=10),
    }
    values.update(updates)
    return PrivilegedIdentitySnapshot(**values)  # type: ignore[arg-type]


def _risk(**updates) -> PrivilegedRiskSnapshot:
    values = {
        "actor_id": "platform-admin",
        "tenant_id": "tenant-a",
        "session_id": "session-a",
        "risk_version": "risk-v1",
        "score": 10,
        "assessed_at": NOW - timedelta(seconds=5),
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(updates)
    return PrivilegedRiskSnapshot(**values)  # type: ignore[arg-type]


def _evidence(request: PrivilegedActionRequest, **updates):
    values = {
        "evidence_id": "step-up-42",
        "request_digest": request.request_digest,
        "actor_id": request.actor.actor_id,
        "tenant_id": request.actor.tenant_id,
        "session_id": request.actor.session_id,
        "policy_digest": request.policy_digest,
        "nonce": request.nonce,
        "assurance": AuthenticationAssurance.PHISHING_RESISTANT,
        "authentication_methods": frozenset({"webauthn"}),
        "authenticated_at": NOW - timedelta(seconds=10),
        "expires_at": NOW + timedelta(minutes=2),
    }
    values.update(updates)
    return StepUpAuthenticationEvidence(**values)  # type: ignore[arg-type]


def _approval(request: PrivilegedActionRequest, **updates):
    values = {
        "approval_id": "approval-42",
        "request_digest": request.request_digest,
        "actor_id": request.actor.actor_id,
        "tenant_id": request.actor.tenant_id,
        "approver_id": "security-reviewer",
        "policy_digest": request.policy_digest,
        "nonce": request.nonce,
        "approved_at": NOW - timedelta(seconds=5),
        "expires_at": NOW + timedelta(minutes=2),
    }
    values.update(updates)
    return PrivilegedApprovalEvidence(**values)  # type: ignore[arg-type]


def _manager(
    policy,
    request,
    evidence,
    approval,
    *,
    identity=None,
    risk=None,
    backend=None,
    store=None,
    audit=None,
):
    identity_provider = identity or IdentityProvider(_identity())
    risk_provider = risk or RiskProvider(_risk())
    backend_authorizer = backend or BackendAuthorizer()
    manager = PrivilegedAccessManager(
        policy,
        identity_provider=identity_provider,
        risk_provider=risk_provider,
        backend_authorizer=backend_authorizer,
        step_up_verifier=StaticStepUpEvidenceVerifier(
            frozenset({(evidence.evidence_id, evidence.evidence_digest)})
        ),
        approval_verifier=StaticPrivilegedApprovalVerifier(
            frozenset({(approval.approval_id, approval.approval_digest)})
        ),
        state_store=store,
        audit_sink=audit,
    )
    return manager, identity_provider, risk_provider, backend_authorizer


def test_exact_step_up_issues_single_use_jit_grant_and_rechecks_backend():
    policy = _policy()
    request = _request(policy)
    evidence = _evidence(request)
    approval = _approval(request)
    audit = MemoryPrivilegedAccessAuditSink()
    manager, identity, risk, backend = _manager(policy, request, evidence, approval, audit=audit)

    grant = manager.require_grant(request, step_up=evidence, approval=approval, now=NOW)
    authorization = manager.require_execution(request, grant, now=NOW)
    replay = manager.authorize_execution(request, grant, now=NOW)

    assert grant.scopes == frozenset({"models:weights:export"})
    assert grant.expires_at == NOW + timedelta(seconds=60)
    assert authorization.backend_authorization_revision == "backend-revision-1"
    assert replay.findings[-1].code == PrivilegedAccessCode.GRANT_REPLAYED
    assert identity.calls == risk.calls == backend.calls == 3
    assert len(audit.events) == 3
    serialized = "".join(item.model_dump_json() for item in audit.events)
    assert "platform-admin" not in serialized
    assert "tenant-a" not in serialized
    assert "private-model-weights-42" not in serialized


def test_missing_step_up_and_approval_requests_elevation_without_activating_access():
    policy = _policy()
    request = _request(policy)
    evidence = _evidence(request)
    approval = _approval(request)
    manager, identity, risk, backend = _manager(policy, request, evidence, approval)

    result = manager.issue_grant(request, step_up=None, approval=None, now=NOW)

    assert result.action == GuardAction.REQUIRE_APPROVAL
    assert {item.code for item in result.findings} == {
        PrivilegedAccessCode.STEP_UP_REQUIRED,
        PrivilegedAccessCode.APPROVAL_REQUIRED,
    }
    assert identity.calls == risk.calls == backend.calls == 0


@pytest.mark.parametrize(
    ("evidence_updates", "expected"),
    [
        ({"nonce": "replayed-nonce"}, PrivilegedAccessCode.STEP_UP_INVALID),
        ({"actor_id": "other-actor"}, PrivilegedAccessCode.STEP_UP_INVALID),
        ({"tenant_id": "tenant-b"}, PrivilegedAccessCode.STEP_UP_INVALID),
        ({"session_id": "session-b"}, PrivilegedAccessCode.STEP_UP_INVALID),
        ({"policy_digest": "0" * 64}, PrivilegedAccessCode.STEP_UP_INVALID),
        (
            {"assurance": AuthenticationAssurance.MULTI_FACTOR},
            PrivilegedAccessCode.ASSURANCE_INSUFFICIENT,
        ),
        (
            {
                "authenticated_at": NOW - timedelta(minutes=3),
                "expires_at": NOW + timedelta(minutes=1),
            },
            PrivilegedAccessCode.STEP_UP_EXPIRED,
        ),
    ],
)
def test_step_up_binding_assurance_and_freshness_bypasses_fail_closed(evidence_updates, expected):
    policy = _policy()
    request = _request(policy)
    evidence = _evidence(request, **evidence_updates)
    approval = _approval(request)
    manager, *_ = _manager(policy, request, evidence, approval)

    result = manager.issue_grant(request, step_up=evidence, approval=approval, now=NOW)

    assert not result.is_allowed
    assert expected in {item.code for item in result.findings}


def test_actor_cannot_approve_their_own_privileged_action():
    policy = _policy(allowed_approver_ids=frozenset({"platform-admin"}))
    request = _request(policy)
    evidence = _evidence(request)
    approval = _approval(request, approver_id="platform-admin")
    manager, *_ = _manager(policy, request, evidence, approval)

    result = manager.issue_grant(request, step_up=evidence, approval=approval, now=NOW)

    assert PrivilegedAccessCode.APPROVER_NOT_INDEPENDENT in {item.code for item in result.findings}


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ("identity", PrivilegedAccessCode.IDENTITY_CHANGED),
        ("role", PrivilegedAccessCode.ROLE_CHANGED),
        ("risk", PrivilegedAccessCode.RISK_CHANGED),
        ("session", PrivilegedAccessCode.SESSION_CHANGED),
    ],
)
def test_grant_is_revoked_when_live_security_context_changes(change, expected):
    policy = _policy()
    request = _request(policy)
    evidence = _evidence(request)
    approval = _approval(request)
    identity = IdentityProvider(_identity())
    risk = RiskProvider(_risk())
    manager, *_ = _manager(
        policy,
        request,
        evidence,
        approval,
        identity=identity,
        risk=risk,
    )
    grant = manager.require_grant(request, step_up=evidence, approval=approval, now=NOW)
    if change == "identity":
        identity.snapshot = _identity(identity_version="identity-v2")
    elif change == "role":
        identity.snapshot = _identity(role_version="roles-v2")
    elif change == "risk":
        risk.snapshot = _risk(risk_version="risk-v2")
    else:
        identity.snapshot = _identity(session_id="session-b")

    result = manager.authorize_execution(request, grant, now=NOW)
    retry = manager.authorize_execution(request, grant, now=NOW)

    assert expected in {item.code for item in result.findings}
    assert PrivilegedAccessCode.GRANT_REVOKED not in {item.code for item in result.findings}
    assert not retry.is_allowed


@pytest.mark.parametrize(
    ("service", "expected"),
    [
        ("identity", PrivilegedAccessCode.IDENTITY_SERVICE_UNAVAILABLE),
        ("risk", PrivilegedAccessCode.RISK_SERVICE_UNAVAILABLE),
        ("backend", PrivilegedAccessCode.AUTHORIZATION_SERVICE_UNAVAILABLE),
    ],
)
def test_authoritative_service_outages_fail_closed(service, expected):
    policy = _policy()
    request = _request(policy)
    evidence = _evidence(request)
    approval = _approval(request)
    identity = IdentityProvider(_identity())
    risk = RiskProvider(_risk())
    backend = BackendAuthorizer()
    target = {"identity": identity, "risk": risk, "backend": backend}[service]
    target.fail = True
    manager, *_ = _manager(
        policy,
        request,
        evidence,
        approval,
        identity=identity,
        risk=risk,
        backend=backend,
    )

    result = manager.issue_grant(request, step_up=evidence, approval=approval, now=NOW)

    assert expected in {item.code for item in result.findings}
    assert result.grant is None


def test_backend_denial_session_limit_and_role_are_enforced():
    policy = _policy(maximum_session_duration_seconds=300)
    request = _request(policy)
    evidence = _evidence(request)
    approval = _approval(request)
    identity = IdentityProvider(
        _identity(
            role_ids=frozenset({"billing-admin"}),
            session_started_at=NOW - timedelta(minutes=10),
        )
    )
    backend = BackendAuthorizer()
    backend.allowed = False
    manager, *_ = _manager(
        policy,
        request,
        evidence,
        approval,
        identity=identity,
        backend=backend,
    )

    result = manager.issue_grant(request, step_up=evidence, approval=approval, now=NOW)
    codes = {item.code for item in result.findings}

    assert PrivilegedAccessCode.ROLE_DENIED in codes
    assert PrivilegedAccessCode.SESSION_DURATION_EXCEEDED in codes
    assert PrivilegedAccessCode.BACKEND_AUTHORIZATION_DENIED in codes


def test_unclassified_operation_and_scope_expansion_are_denied():
    policy = _policy()
    request = _request(
        policy,
        operation=PrivilegedAIOperation.MODEL_DEPLOY,
        requested_scopes=frozenset({"models:weights:export", "models:deploy"}),
    )
    evidence = _evidence(request)
    approval = _approval(request)
    manager, *_ = _manager(policy, request, evidence, approval)

    result = manager.issue_grant(request, step_up=evidence, approval=approval, now=NOW)

    assert result.findings[0].code == PrivilegedAccessCode.OPERATION_NOT_CLASSIFIED


def test_explicit_session_revocation_and_typed_error():
    policy = _policy()
    request = _request(policy)
    evidence = _evidence(request)
    approval = _approval(request)
    store = MemoryPrivilegeGrantStateStore()
    manager, *_ = _manager(policy, request, evidence, approval, store=store)
    grant = manager.require_grant(request, step_up=evidence, approval=approval, now=NOW)

    assert manager.revoke_session("session-a") == 1
    with pytest.raises(PrivilegedAccessError) as raised:
        manager.require_execution(request, grant, now=NOW)

    assert raised.value.result.findings[-1].code == PrivilegedAccessCode.GRANT_REVOKED
