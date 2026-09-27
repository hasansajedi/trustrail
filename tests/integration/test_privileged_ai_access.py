"""End-to-end step-up and JIT lifecycle for privileged AI operations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from trustrail import (
    AuthenticationAssurance,
    BackendAuthorizationDecision,
    MemoryPrivilegedAccessAuditSink,
    MemoryPrivilegeGrantStateStore,
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

NOW = datetime(2026, 9, 27, 14, tzinfo=UTC)


class LiveIdentity:
    def get_identity(self, actor_id, tenant_id, session_id, now):
        return PrivilegedIdentitySnapshot(
            actor_id=actor_id,
            tenant_id=tenant_id,
            session_id=session_id,
            identity_version="identity-v7",
            role_version="roles-v12",
            role_ids=frozenset({"ai-platform-security"}),
            active=True,
            session_started_at=NOW - timedelta(minutes=2),
            session_expires_at=NOW + timedelta(minutes=8),
        )


class LiveRisk:
    def get_risk(self, actor_id, tenant_id, session_id, now):
        return PrivilegedRiskSnapshot(
            actor_id=actor_id,
            tenant_id=tenant_id,
            session_id=session_id,
            risk_version="risk-v3",
            score=5,
            assessed_at=NOW - timedelta(seconds=5),
            expires_at=NOW + timedelta(minutes=3),
        )


class LiveBackendAuthorization:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def authorize(self, request, identity, now):
        self.calls.append(request.request_digest)
        return BackendAuthorizationDecision(
            request_digest=request.request_digest,
            allowed=True,
            authorization_revision=f"resource-acl-{len(self.calls)}",
            reason_code="explicit-allow",
            expires_at=now + timedelta(seconds=45),
        )


def test_all_privileged_ai_operations_require_fresh_single_use_activation():
    scopes = {
        operation: frozenset({f"ai:{operation.value}"}) for operation in PrivilegedAIOperation
    }
    policy = PrivilegedAccessPolicy(
        policy_id="production-privileged-ai-policy",
        version=4,
        operations=tuple(
            PrivilegedOperationPolicy(
                operation=operation,
                required_scopes=scopes[operation],
                eligible_role_ids=frozenset({"ai-platform-security"}),
                minimum_assurance=AuthenticationAssurance.PHISHING_RESISTANT,
                allowed_approver_ids=frozenset({"security-duty-manager"}),
                maximum_session_duration_seconds=900,
                maximum_step_up_age_seconds=120,
                maximum_grant_ttl_seconds=30,
                maximum_risk_score=20,
            )
            for operation in PrivilegedAIOperation
        ),
    )
    actor = PrivilegedActorContext(
        actor_id="private-platform-operator",
        tenant_id="private-tenant",
        session_id="private-session",
        identity_version="identity-v7",
        role_version="roles-v12",
        risk_version="risk-v3",
    )
    requests = tuple(
        PrivilegedActionRequest(
            request_id=f"request-{index}",
            actor=actor,
            operation=operation,
            target_id=f"private-{operation.value}-target",
            purpose_id="approved-platform-maintenance",
            requested_scopes=scopes[operation],
            policy_id=policy.policy_id,
            policy_version=policy.version,
            policy_digest=policy.policy_digest,
            nonce=f"nonce-{index}",
        )
        for index, operation in enumerate(PrivilegedAIOperation)
    )
    step_ups = tuple(
        StepUpAuthenticationEvidence(
            evidence_id=f"step-up-{index}",
            request_digest=request.request_digest,
            actor_id=actor.actor_id,
            tenant_id=actor.tenant_id,
            session_id=actor.session_id,
            policy_digest=policy.policy_digest,
            nonce=request.nonce,
            assurance=AuthenticationAssurance.PHISHING_RESISTANT,
            authentication_methods=frozenset({"webauthn"}),
            authenticated_at=NOW,
            expires_at=NOW + timedelta(minutes=2),
        )
        for index, request in enumerate(requests)
    )
    approvals = tuple(
        PrivilegedApprovalEvidence(
            approval_id=f"approval-{index}",
            request_digest=request.request_digest,
            actor_id=actor.actor_id,
            tenant_id=actor.tenant_id,
            approver_id="security-duty-manager",
            policy_digest=policy.policy_digest,
            nonce=request.nonce,
            approved_at=NOW,
            expires_at=NOW + timedelta(minutes=2),
        )
        for index, request in enumerate(requests)
    )
    backend = LiveBackendAuthorization()
    audit = MemoryPrivilegedAccessAuditSink()
    manager = PrivilegedAccessManager(
        policy,
        identity_provider=LiveIdentity(),
        risk_provider=LiveRisk(),
        backend_authorizer=backend,
        step_up_verifier=StaticStepUpEvidenceVerifier(
            frozenset((item.evidence_id, item.evidence_digest) for item in step_ups)
        ),
        approval_verifier=StaticPrivilegedApprovalVerifier(
            frozenset((item.approval_id, item.approval_digest) for item in approvals)
        ),
        state_store=MemoryPrivilegeGrantStateStore(),
        audit_sink=audit,
    )

    for request, step_up, approval in zip(requests, step_ups, approvals, strict=True):
        grant = manager.require_grant(
            request,
            step_up=step_up,
            approval=approval,
            now=NOW,
        )
        permit = manager.require_execution(request, grant, now=NOW)
        assert permit.operation == request.operation
        assert permit.scopes == request.requested_scopes
        assert permit.target_ref == request.target_ref

    assert len(backend.calls) == len(PrivilegedAIOperation) * 2
    assert len(audit.events) == len(PrivilegedAIOperation) * 2
    serialized = "".join(item.model_dump_json() for item in audit.events)
    assert "private-platform-operator" not in serialized
    assert "private-tenant" not in serialized
    assert "private-" not in serialized
