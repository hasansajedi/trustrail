"""Step-up authentication and zero-standing-privilege AI access."""

from __future__ import annotations

import contextlib
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Literal, Protocol, cast

from trustrail.exceptions import PrivilegedAccessError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.privileged_access import (
    AuthorizedPrivilegedOperation,
    BackendAuthorizationDecision,
    JITPrivilegeGrant,
    PrivilegedAccessAuditEvent,
    PrivilegedAccessCode,
    PrivilegedAccessDecision,
    PrivilegedAccessFinding,
    PrivilegedAccessPhase,
    PrivilegedAccessPolicy,
    PrivilegedActionRequest,
    PrivilegedApprovalEvidence,
    PrivilegedIdentitySnapshot,
    PrivilegedOperationPolicy,
    PrivilegedRiskSnapshot,
    PrivilegeGrantStateStatus,
    StepUpAuthenticationEvidence,
    privileged_access_digest,
    privileged_access_reference,
    utcnow,
)


class PrivilegedIdentityProvider(Protocol):
    """Return current identity, role, and session state from an authority."""

    def get_identity(
        self,
        actor_id: str,
        tenant_id: str,
        session_id: str,
        now: datetime,
    ) -> PrivilegedIdentitySnapshot | None: ...


class PrivilegedRiskProvider(Protocol):
    """Return current risk state for an exact actor session."""

    def get_risk(
        self,
        actor_id: str,
        tenant_id: str,
        session_id: str,
        now: datetime,
    ) -> PrivilegedRiskSnapshot | None: ...


class BackendAuthorizationProvider(Protocol):
    """Reauthorize an exact request at its authoritative resource backend."""

    def authorize(
        self,
        request: PrivilegedActionRequest,
        identity: PrivilegedIdentitySnapshot,
        now: datetime,
    ) -> BackendAuthorizationDecision: ...


class StepUpEvidenceVerifier(Protocol):
    """Authenticate step-up evidence from an out-of-band identity service."""

    def verify_step_up(self, evidence: StepUpAuthenticationEvidence) -> bool: ...


class PrivilegedApprovalVerifier(Protocol):
    """Authenticate independent approval evidence."""

    def verify_approval(self, evidence: PrivilegedApprovalEvidence) -> bool: ...


class PrivilegeGrantStateStore(Protocol):
    """Atomically register, consume, and revoke exact JIT grants."""

    def register(self, grant: JITPrivilegeGrant) -> PrivilegeGrantStateStatus: ...

    def consume(
        self,
        grant_id: str,
        grant_digest: str,
        now: datetime,
    ) -> PrivilegeGrantStateStatus: ...

    def revoke(self, grant_id: str) -> PrivilegeGrantStateStatus: ...

    def revoke_session(self, session_ref: str) -> int: ...


class PrivilegedAccessAuditSink(Protocol):
    """Persist content-free privileged-access decisions."""

    def emit(self, event: PrivilegedAccessAuditEvent) -> None: ...


class MemoryPrivilegeGrantStateStore:
    """Process-local atomic JIT state for tests and single-worker deployments."""

    def __init__(self, max_grants: int = 10_000) -> None:
        if max_grants < 1:
            raise ValueError("max_grants must be at least 1")
        self._max_grants = max_grants
        self._grants: dict[str, tuple[str, str, datetime, PrivilegeGrantStateStatus]] = {}
        self._lock = threading.Lock()

    def register(self, grant: JITPrivilegeGrant) -> PrivilegeGrantStateStatus:
        with self._lock:
            existing = self._grants.get(grant.grant_id)
            if existing is not None:
                return (
                    PrivilegeGrantStateStatus.REPLAYED
                    if existing[0] == grant.grant_digest
                    else PrivilegeGrantStateStatus.COLLISION
                )
            if len(self._grants) >= self._max_grants:
                return PrivilegeGrantStateStatus.COLLISION
            self._grants[grant.grant_id] = (
                grant.grant_digest,
                grant.session_ref,
                grant.expires_at,
                PrivilegeGrantStateStatus.STORED,
            )
            return PrivilegeGrantStateStatus.STORED

    def consume(
        self,
        grant_id: str,
        grant_digest: str,
        now: datetime,
    ) -> PrivilegeGrantStateStatus:
        with self._lock:
            existing = self._grants.get(grant_id)
            if existing is None or existing[0] != grant_digest:
                return PrivilegeGrantStateStatus.MISSING
            digest, session_ref, expires_at, status = existing
            if status == PrivilegeGrantStateStatus.REVOKED:
                return status
            if status == PrivilegeGrantStateStatus.CONSUMED:
                return PrivilegeGrantStateStatus.REPLAYED
            if now >= expires_at:
                self._grants[grant_id] = (
                    digest,
                    session_ref,
                    expires_at,
                    PrivilegeGrantStateStatus.EXPIRED,
                )
                return PrivilegeGrantStateStatus.EXPIRED
            self._grants[grant_id] = (
                digest,
                session_ref,
                expires_at,
                PrivilegeGrantStateStatus.CONSUMED,
            )
            return PrivilegeGrantStateStatus.CONSUMED

    def revoke(self, grant_id: str) -> PrivilegeGrantStateStatus:
        with self._lock:
            existing = self._grants.get(grant_id)
            if existing is None:
                return PrivilegeGrantStateStatus.MISSING
            digest, session_ref, expires_at, _ = existing
            self._grants[grant_id] = (
                digest,
                session_ref,
                expires_at,
                PrivilegeGrantStateStatus.REVOKED,
            )
            return PrivilegeGrantStateStatus.REVOKED

    def revoke_session(self, session_ref: str) -> int:
        with self._lock:
            revoked = 0
            for grant_id, (digest, stored_session, expires_at, status) in list(
                self._grants.items()
            ):
                if stored_session == session_ref and status == PrivilegeGrantStateStatus.STORED:
                    self._grants[grant_id] = (
                        digest,
                        stored_session,
                        expires_at,
                        PrivilegeGrantStateStatus.REVOKED,
                    )
                    revoked += 1
            return revoked


class MemoryPrivilegedAccessAuditSink:
    """Bounded process-local audit sink for tests and development."""

    def __init__(self, max_events: int = 1_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._events: deque[PrivilegedAccessAuditEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def emit(self, event: PrivilegedAccessAuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> list[PrivilegedAccessAuditEvent]:
        with self._lock:
            return list(self._events)


class StaticStepUpEvidenceVerifier:
    """Exact-digest verifier for tests and trusted adapter implementations."""

    def __init__(self, accepted_evidence: frozenset[tuple[str, str]]) -> None:
        self._accepted = accepted_evidence

    def verify_step_up(self, evidence: StepUpAuthenticationEvidence) -> bool:
        return (evidence.evidence_id, evidence.evidence_digest) in self._accepted


class StaticPrivilegedApprovalVerifier:
    """Exact-digest verifier for tests and trusted adapter implementations."""

    def __init__(self, accepted_evidence: frozenset[tuple[str, str]]) -> None:
        self._accepted = accepted_evidence

    def verify_approval(self, evidence: PrivilegedApprovalEvidence) -> bool:
        return (evidence.approval_id, evidence.approval_digest) in self._accepted


class PrivilegedAccessManager:
    """Issue and consume exact JIT grants with complete live reauthorization."""

    def __init__(
        self,
        policy: PrivilegedAccessPolicy,
        *,
        identity_provider: PrivilegedIdentityProvider,
        risk_provider: PrivilegedRiskProvider,
        backend_authorizer: BackendAuthorizationProvider,
        step_up_verifier: StepUpEvidenceVerifier,
        approval_verifier: PrivilegedApprovalVerifier | None = None,
        state_store: PrivilegeGrantStateStore | None = None,
        audit_sink: PrivilegedAccessAuditSink | None = None,
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._identity_provider = identity_provider
        self._risk_provider = risk_provider
        self._backend_authorizer = backend_authorizer
        self._step_up_verifier = step_up_verifier
        self._approval_verifier = approval_verifier
        self._state_store = state_store or MemoryPrivilegeGrantStateStore()
        self._audit_sink = audit_sink

    @property
    def policy(self) -> PrivilegedAccessPolicy:
        return self._policy.model_copy(deep=True)

    def issue_grant(
        self,
        request: PrivilegedActionRequest,
        *,
        step_up: StepUpAuthenticationEvidence | None,
        approval: PrivilegedApprovalEvidence | None = None,
        now: datetime | None = None,
    ) -> PrivilegedAccessDecision:
        """Issue one exact JIT grant after fresh authentication and authorization."""
        current_time = now or utcnow()
        rule, findings = self._policy_findings(request)
        if rule is not None:
            findings.extend(self._step_up_findings(request, rule, step_up, current_time))
            findings.extend(self._approval_findings(request, rule, approval, current_time))

        missing = {
            PrivilegedAccessCode.STEP_UP_REQUIRED,
            PrivilegedAccessCode.APPROVAL_REQUIRED,
        }
        if any(item.code in missing for item in findings):
            return self._decision(
                request,
                PrivilegedAccessPhase.ISSUE,
                findings,
                current_time,
                action=GuardAction.REQUIRE_APPROVAL,
            )

        identity = None
        risk = None
        backend = None
        if rule is not None and not findings:
            identity, risk, backend, current_findings = self._current_authority(
                request, rule, current_time
            )
            findings.extend(current_findings)

        grant: JITPrivilegeGrant | None = None
        if (
            rule is not None
            and step_up is not None
            and identity is not None
            and risk is not None
            and backend is not None
            and not findings
        ):
            expiry_candidates = [
                current_time + timedelta(seconds=rule.maximum_grant_ttl_seconds),
                identity.session_expires_at,
                risk.expires_at,
                backend.expires_at,
                step_up.expires_at,
            ]
            if approval is not None:
                expiry_candidates.append(approval.expires_at)
            expires_at = min(expiry_candidates)
            grant_seed = privileged_access_digest(
                {"request": request.request_digest, "nonce": request.nonce}
            )
            grant_id = f"jit-{grant_seed[:32]}"
            grant = JITPrivilegeGrant.create(
                grant_id=grant_id,
                request_digest=request.request_digest,
                actor_ref=privileged_access_reference(request.actor.actor_id),
                tenant_ref=privileged_access_reference(request.actor.tenant_id),
                session_ref=privileged_access_reference(request.actor.session_id),
                operation=request.operation,
                target_ref=request.target_ref,
                scopes=request.requested_scopes,
                policy_digest=self._policy.policy_digest,
                identity_version=identity.identity_version,
                role_version=identity.role_version,
                risk_version=risk.risk_version,
                step_up_evidence_digest=step_up.evidence_digest,
                approval_evidence_digest=(
                    approval.approval_digest if approval is not None else None
                ),
                issued_at=current_time,
                expires_at=expires_at,
            )
            try:
                status = self._state_store.register(grant)
            except Exception:
                status = None
            if status != PrivilegeGrantStateStatus.STORED:
                code = (
                    PrivilegedAccessCode.GRANT_REPLAYED
                    if status == PrivilegeGrantStateStatus.REPLAYED
                    else PrivilegedAccessCode.GRANT_STATE_UNAVAILABLE
                )
                findings.append(_finding(code, "JIT grant could not be registered atomically"))
                grant = None

        return self._decision(
            request,
            PrivilegedAccessPhase.ISSUE,
            findings,
            current_time,
            grant=grant,
        )

    def require_grant(
        self,
        request: PrivilegedActionRequest,
        *,
        step_up: StepUpAuthenticationEvidence | None,
        approval: PrivilegedApprovalEvidence | None = None,
        now: datetime | None = None,
    ) -> JITPrivilegeGrant:
        """Return a JIT grant or raise before privileged credentials are activated."""
        result = self.issue_grant(
            request,
            step_up=step_up,
            approval=approval,
            now=now,
        )
        if not result.is_allowed or result.grant is None:
            raise PrivilegedAccessError(result)
        return result.grant

    def authorize_execution(
        self,
        request: PrivilegedActionRequest,
        grant: JITPrivilegeGrant,
        *,
        now: datetime | None = None,
    ) -> PrivilegedAccessDecision:
        """Reauthorize live state and atomically consume a grant for one action."""
        current_time = now or utcnow()
        rule, findings = self._policy_findings(request)
        findings.extend(self._grant_binding_findings(request, grant, current_time))

        identity = None
        risk = None
        backend = None
        if rule is not None and not findings:
            identity, risk, backend, current_findings = self._current_authority(
                request, rule, current_time
            )
            findings.extend(current_findings)
        if identity is not None:
            if identity.identity_version != grant.identity_version:
                findings.append(
                    _finding(
                        PrivilegedAccessCode.IDENTITY_CHANGED,
                        "Identity changed after JIT grant issuance",
                    )
                )
            if identity.role_version != grant.role_version:
                findings.append(
                    _finding(
                        PrivilegedAccessCode.ROLE_CHANGED,
                        "Roles changed after JIT grant issuance",
                    )
                )
        if risk is not None and risk.risk_version != grant.risk_version:
            findings.append(
                _finding(
                    PrivilegedAccessCode.RISK_CHANGED,
                    "Risk state changed after JIT grant issuance",
                )
            )
        if grant.policy_digest != self._policy.policy_digest:
            findings.append(
                _finding(
                    PrivilegedAccessCode.POLICY_CHANGED,
                    "Privileged access policy changed after grant issuance",
                )
            )

        if any(
            item.code
            in {
                PrivilegedAccessCode.IDENTITY_CHANGED,
                PrivilegedAccessCode.ROLE_CHANGED,
                PrivilegedAccessCode.POLICY_CHANGED,
                PrivilegedAccessCode.RISK_CHANGED,
                PrivilegedAccessCode.SESSION_CHANGED,
                PrivilegedAccessCode.IDENTITY_INACTIVE,
                PrivilegedAccessCode.RISK_DENIED,
            }
            for item in findings
        ):
            with contextlib.suppress(Exception):
                self._state_store.revoke(grant.grant_id)

        authorization: AuthorizedPrivilegedOperation | None = None
        if backend is not None and not findings:
            try:
                status = self._state_store.consume(grant.grant_id, grant.grant_digest, current_time)
            except Exception:
                status = None
            state_finding = _grant_state_finding(status)
            if state_finding is not None:
                findings.append(state_finding)
            else:
                expires_at = min(grant.expires_at, backend.expires_at)
                authorization = AuthorizedPrivilegedOperation(
                    authorization_id=privileged_access_digest(
                        {
                            "request": request.request_digest,
                            "grant": grant.grant_digest,
                            "backend_revision": backend.authorization_revision,
                        }
                    ),
                    request_digest=request.request_digest,
                    grant_digest=grant.grant_digest,
                    actor_ref=grant.actor_ref,
                    tenant_ref=grant.tenant_ref,
                    operation=request.operation,
                    target_ref=request.target_ref,
                    scopes=request.requested_scopes,
                    backend_authorization_revision=backend.authorization_revision,
                    expires_at=expires_at,
                )

        return self._decision(
            request,
            PrivilegedAccessPhase.EXECUTE,
            findings,
            current_time,
            authorization=authorization,
            grant_ref=privileged_access_reference(grant.grant_id),
        )

    def require_execution(
        self,
        request: PrivilegedActionRequest,
        grant: JITPrivilegeGrant,
        *,
        now: datetime | None = None,
    ) -> AuthorizedPrivilegedOperation:
        """Return an exact execution permit or raise before a privileged action."""
        result = self.authorize_execution(request, grant, now=now)
        if not result.is_allowed or result.authorization is None:
            raise PrivilegedAccessError(result)
        return result.authorization

    def revoke_session(self, session_id: str) -> int:
        """Revoke all locally known unused grants for an invalidated session."""
        try:
            return self._state_store.revoke_session(privileged_access_reference(session_id))
        except Exception as error:
            raise RuntimeError("JIT grant state is unavailable") from error

    def _policy_findings(
        self, request: PrivilegedActionRequest
    ) -> tuple[PrivilegedOperationPolicy | None, list[PrivilegedAccessFinding]]:
        findings: list[PrivilegedAccessFinding] = []
        rule = self._policy.policy_for(request.operation)
        if rule is None:
            findings.append(
                _finding(
                    PrivilegedAccessCode.OPERATION_NOT_CLASSIFIED,
                    "Privileged AI operation has no explicit policy classification",
                )
            )
            return None, findings
        if (
            request.policy_id != self._policy.policy_id
            or request.policy_version != self._policy.version
            or request.policy_digest != self._policy.policy_digest
        ):
            findings.append(
                _finding(
                    PrivilegedAccessCode.POLICY_MISMATCH,
                    "Request is not bound to the current privileged access policy",
                )
            )
        if request.requested_scopes != rule.required_scopes:
            findings.append(
                _finding(
                    PrivilegedAccessCode.SCOPE_DENIED,
                    "Requested scopes do not exactly match the classified operation",
                )
            )
        return rule, findings

    def _step_up_findings(
        self,
        request: PrivilegedActionRequest,
        rule: PrivilegedOperationPolicy,
        evidence: StepUpAuthenticationEvidence | None,
        now: datetime,
    ) -> list[PrivilegedAccessFinding]:
        if evidence is None:
            return [
                _finding(
                    PrivilegedAccessCode.STEP_UP_REQUIRED,
                    "Fresh step-up authentication is required",
                    Severity.HIGH,
                )
            ]
        bindings_valid = (
            evidence.request_digest == request.request_digest
            and evidence.actor_id == request.actor.actor_id
            and evidence.tenant_id == request.actor.tenant_id
            and evidence.session_id == request.actor.session_id
            and evidence.policy_digest == self._policy.policy_digest
            and evidence.nonce == request.nonce
        )
        findings: list[PrivilegedAccessFinding] = []
        try:
            verified = self._step_up_verifier.verify_step_up(evidence)
        except Exception:
            findings.append(
                _finding(
                    PrivilegedAccessCode.STEP_UP_SERVICE_UNAVAILABLE,
                    "Step-up authentication service is unavailable",
                )
            )
            verified = False
        if not findings and (not bindings_valid or not verified):
            findings.append(
                _finding(
                    PrivilegedAccessCode.STEP_UP_INVALID,
                    "Step-up evidence is not valid for this exact request",
                )
            )
        if (
            now < evidence.authenticated_at
            or now >= evidence.expires_at
            or (now - evidence.authenticated_at).total_seconds() > rule.maximum_step_up_age_seconds
        ):
            findings.append(
                _finding(
                    PrivilegedAccessCode.STEP_UP_EXPIRED,
                    "Step-up evidence is not fresh",
                    Severity.HIGH,
                )
            )
        if evidence.assurance < rule.minimum_assurance:
            findings.append(
                _finding(
                    PrivilegedAccessCode.ASSURANCE_INSUFFICIENT,
                    "Authentication assurance is below the classified requirement",
                    Severity.HIGH,
                )
            )
        return findings

    def _approval_findings(
        self,
        request: PrivilegedActionRequest,
        rule: PrivilegedOperationPolicy,
        evidence: PrivilegedApprovalEvidence | None,
        now: datetime,
    ) -> list[PrivilegedAccessFinding]:
        if not rule.require_independent_approval:
            if evidence is not None:
                return [
                    _finding(
                        PrivilegedAccessCode.APPROVAL_INVALID,
                        "Approval was supplied for an operation that does not require it",
                        Severity.HIGH,
                    )
                ]
            return []
        if evidence is None:
            return [
                _finding(
                    PrivilegedAccessCode.APPROVAL_REQUIRED,
                    "Independent approval is required",
                    Severity.HIGH,
                )
            ]
        findings: list[PrivilegedAccessFinding] = []
        if evidence.approver_id == request.actor.actor_id:
            findings.append(
                _finding(
                    PrivilegedAccessCode.APPROVER_NOT_INDEPENDENT,
                    "Actor cannot approve their own privileged action",
                )
            )
        bindings_valid = (
            evidence.request_digest == request.request_digest
            and evidence.actor_id == request.actor.actor_id
            and evidence.tenant_id == request.actor.tenant_id
            and evidence.approver_id in rule.allowed_approver_ids
            and evidence.policy_digest == self._policy.policy_digest
            and evidence.nonce == request.nonce
            and evidence.approved_at <= now < evidence.expires_at
        )
        if self._approval_verifier is None:
            findings.append(
                _finding(
                    PrivilegedAccessCode.APPROVAL_SERVICE_UNAVAILABLE,
                    "Independent approval service is unavailable",
                )
            )
            return findings
        try:
            verified = self._approval_verifier.verify_approval(evidence)
        except Exception:
            findings.append(
                _finding(
                    PrivilegedAccessCode.APPROVAL_SERVICE_UNAVAILABLE,
                    "Independent approval service is unavailable",
                )
            )
            return findings
        if not bindings_valid or not verified:
            findings.append(
                _finding(
                    PrivilegedAccessCode.APPROVAL_INVALID,
                    "Approval is not valid for this exact request",
                )
            )
        return findings

    def _current_authority(
        self,
        request: PrivilegedActionRequest,
        rule: PrivilegedOperationPolicy,
        now: datetime,
    ) -> tuple[
        PrivilegedIdentitySnapshot | None,
        PrivilegedRiskSnapshot | None,
        BackendAuthorizationDecision | None,
        list[PrivilegedAccessFinding],
    ]:
        findings: list[PrivilegedAccessFinding] = []
        try:
            identity = self._identity_provider.get_identity(
                request.actor.actor_id,
                request.actor.tenant_id,
                request.actor.session_id,
                now,
            )
        except Exception:
            identity = None
            findings.append(
                _finding(
                    PrivilegedAccessCode.IDENTITY_SERVICE_UNAVAILABLE,
                    "Identity and role service is unavailable",
                )
            )
        if identity is None:
            if not findings:
                findings.append(
                    _finding(
                        PrivilegedAccessCode.IDENTITY_INACTIVE,
                        "Identity or session is not active",
                    )
                )
            return None, None, None, findings

        expected_context = (
            request.actor.actor_id,
            request.actor.tenant_id,
            request.actor.session_id,
        )
        if (identity.actor_id, identity.tenant_id) != expected_context[:2]:
            findings.append(
                _finding(
                    PrivilegedAccessCode.ACTOR_CONTEXT_MISMATCH,
                    "Identity response does not match the requested actor context",
                )
            )
        if identity.session_id != request.actor.session_id:
            findings.append(
                _finding(
                    PrivilegedAccessCode.SESSION_CHANGED,
                    "Identity response belongs to a different session",
                )
            )
        if not identity.active:
            findings.append(
                _finding(
                    PrivilegedAccessCode.IDENTITY_INACTIVE,
                    "Identity is inactive",
                )
            )
        if now < identity.session_started_at or now >= identity.session_expires_at:
            findings.append(
                _finding(
                    PrivilegedAccessCode.SESSION_EXPIRED,
                    "Privileged session is outside its usable lifetime",
                    Severity.HIGH,
                )
            )
        if (
            identity.session_expires_at - identity.session_started_at
        ).total_seconds() > rule.maximum_session_duration_seconds:
            findings.append(
                _finding(
                    PrivilegedAccessCode.SESSION_DURATION_EXCEEDED,
                    "Session duration exceeds the classified maximum",
                    Severity.HIGH,
                )
            )
        if not identity.role_ids.intersection(rule.eligible_role_ids):
            findings.append(
                _finding(
                    PrivilegedAccessCode.ROLE_DENIED,
                    "Current roles are not eligible for this privileged operation",
                )
            )
        if request.actor.identity_version != identity.identity_version:
            findings.append(
                _finding(
                    PrivilegedAccessCode.IDENTITY_CHANGED,
                    "Request identity version is stale",
                )
            )
        if request.actor.role_version != identity.role_version:
            findings.append(
                _finding(
                    PrivilegedAccessCode.ROLE_CHANGED,
                    "Request role version is stale",
                )
            )

        try:
            risk = self._risk_provider.get_risk(
                request.actor.actor_id,
                request.actor.tenant_id,
                request.actor.session_id,
                now,
            )
        except Exception:
            risk = None
            findings.append(
                _finding(
                    PrivilegedAccessCode.RISK_SERVICE_UNAVAILABLE,
                    "Risk service is unavailable",
                )
            )
        if risk is None:
            if not any(
                item.code == PrivilegedAccessCode.RISK_SERVICE_UNAVAILABLE for item in findings
            ):
                findings.append(
                    _finding(
                        PrivilegedAccessCode.RISK_DENIED,
                        "Current risk state is unavailable or denied",
                    )
                )
            return identity, None, None, findings
        if (
            (risk.actor_id, risk.tenant_id, risk.session_id) != expected_context
            or now < risk.assessed_at
            or now >= risk.expires_at
            or risk.blocked
            or risk.score > rule.maximum_risk_score
        ):
            findings.append(
                _finding(
                    PrivilegedAccessCode.RISK_DENIED,
                    "Current risk state does not permit privileged access",
                )
            )
        if request.actor.risk_version != risk.risk_version:
            findings.append(
                _finding(
                    PrivilegedAccessCode.RISK_CHANGED,
                    "Request risk version is stale",
                )
            )

        try:
            backend = self._backend_authorizer.authorize(request, identity, now)
        except Exception:
            backend = None
            findings.append(
                _finding(
                    PrivilegedAccessCode.AUTHORIZATION_SERVICE_UNAVAILABLE,
                    "Authoritative backend authorization is unavailable",
                )
            )
        if backend is None:
            return identity, risk, None, findings
        if (
            not backend.allowed
            or backend.request_digest != request.request_digest
            or now >= backend.expires_at
        ):
            findings.append(
                _finding(
                    PrivilegedAccessCode.BACKEND_AUTHORIZATION_DENIED,
                    "Authoritative backend denied the exact privileged action",
                )
            )
        return identity, risk, backend, findings

    def _grant_binding_findings(
        self,
        request: PrivilegedActionRequest,
        grant: JITPrivilegeGrant,
        now: datetime,
    ) -> list[PrivilegedAccessFinding]:
        if not grant.has_valid_integrity:
            return [
                _finding(
                    PrivilegedAccessCode.GRANT_INVALID,
                    "JIT grant integrity is invalid",
                )
            ]
        if now < grant.issued_at or now >= grant.expires_at:
            return [
                _finding(
                    PrivilegedAccessCode.GRANT_EXPIRED,
                    "JIT grant is outside its usable lifetime",
                    Severity.HIGH,
                )
            ]
        if (
            grant.request_digest != request.request_digest
            or grant.actor_ref != privileged_access_reference(request.actor.actor_id)
            or grant.tenant_ref != privileged_access_reference(request.actor.tenant_id)
            or grant.session_ref != privileged_access_reference(request.actor.session_id)
            or grant.operation != request.operation
            or grant.target_ref != request.target_ref
            or grant.scopes != request.requested_scopes
        ):
            return [
                _finding(
                    PrivilegedAccessCode.GRANT_INVALID,
                    "JIT grant is not bound to this exact privileged action",
                )
            ]
        return []

    def _decision(
        self,
        request: PrivilegedActionRequest,
        phase: PrivilegedAccessPhase,
        findings: list[PrivilegedAccessFinding],
        now: datetime,
        *,
        action: GuardAction | None = None,
        grant: JITPrivilegeGrant | None = None,
        authorization: AuthorizedPrivilegedOperation | None = None,
        grant_ref: str | None = None,
    ) -> PrivilegedAccessDecision:
        if action is None:
            action = (
                GuardAction.ALLOW
                if grant is not None or authorization is not None
                else GuardAction.BLOCK
            )
        code = PrivilegedAccessCode.ALLOWED if action == GuardAction.ALLOW else findings[0].code
        audit = PrivilegedAccessAuditEvent(
            occurred_at=now,
            phase=phase,
            action=action,
            code=code,
            request_ref=privileged_access_reference(request.request_id),
            actor_ref=privileged_access_reference(request.actor.actor_id),
            tenant_ref=privileged_access_reference(request.actor.tenant_id),
            target_ref=request.target_ref,
            operation=request.operation,
            grant_ref=(
                grant_ref
                or (privileged_access_reference(grant.grant_id) if grant is not None else None)
            ),
        )
        self._publish(audit)
        return PrivilegedAccessDecision(
            action=cast(
                Literal[
                    GuardAction.ALLOW,
                    GuardAction.BLOCK,
                    GuardAction.REQUIRE_APPROVAL,
                ],
                action,
            ),
            findings=tuple(_deduplicate(findings)),
            grant=grant,
            authorization=authorization,
            audit_event=audit,
        )

    def _publish(self, event: PrivilegedAccessAuditEvent) -> None:
        if self._audit_sink is not None:
            with contextlib.suppress(Exception):
                self._audit_sink.emit(event)


def _grant_state_finding(
    status: PrivilegeGrantStateStatus | None,
) -> PrivilegedAccessFinding | None:
    if status == PrivilegeGrantStateStatus.CONSUMED:
        return None
    if status == PrivilegeGrantStateStatus.REPLAYED:
        return _finding(
            PrivilegedAccessCode.GRANT_REPLAYED,
            "JIT grant was already consumed",
        )
    if status == PrivilegeGrantStateStatus.REVOKED:
        return _finding(
            PrivilegedAccessCode.GRANT_REVOKED,
            "JIT grant was revoked",
        )
    if status == PrivilegeGrantStateStatus.EXPIRED:
        return _finding(
            PrivilegedAccessCode.GRANT_EXPIRED,
            "JIT grant expired before atomic consumption",
            Severity.HIGH,
        )
    if status == PrivilegeGrantStateStatus.MISSING:
        return _finding(
            PrivilegedAccessCode.GRANT_INVALID,
            "JIT grant is not registered",
        )
    return _finding(
        PrivilegedAccessCode.GRANT_STATE_UNAVAILABLE,
        "JIT grant state is unavailable",
    )


def _finding(
    code: PrivilegedAccessCode,
    message: str,
    severity: Severity = Severity.CRITICAL,
) -> PrivilegedAccessFinding:
    return PrivilegedAccessFinding(code=code, severity=severity, message=message)


def _deduplicate(
    findings: list[PrivilegedAccessFinding],
) -> list[PrivilegedAccessFinding]:
    unique: list[PrivilegedAccessFinding] = []
    seen: set[PrivilegedAccessCode] = set()
    for finding in findings:
        if finding.code not in seen:
            unique.append(finding)
            seen.add(finding.code)
    return unique
