"""Identity-bound, short-lived delegated privileges for agent workloads."""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta
from typing import Protocol

from trustrail.exceptions import DelegatedIdentityError
from trustrail.models.agency import ToolPrincipal
from trustrail.models.delegated_identity import (
    AgentIdentityKind,
    AuthorizedDelegatedAccess,
    DelegatedAccessCode,
    DelegatedAccessFinding,
    DelegatedAccessGrant,
    DelegatedAccessGrantKind,
    DelegatedAccessPolicy,
    DelegatedAccessRequest,
    DelegatedAccessResult,
    DelegatedCapability,
    DelegationChain,
    DelegationRevocation,
    utcnow,
)
from trustrail.models.enums import GuardAction, Severity


class DelegatedCapabilityVerifier(Protocol):
    """Authenticate a capability against trusted issuance state or a signature."""

    def verify_capability(self, capability: DelegatedCapability) -> bool:
        """Return whether trusted application state issued this exact capability."""
        ...


class DelegatedAccessGrantVerifier(Protocol):
    """Authenticate step-up and just-in-time access grants."""

    def verify_grant(self, grant: DelegatedAccessGrant) -> bool:
        """Return whether trusted application state issued this exact grant."""
        ...


class DelegationRevocationProvider(Protocol):
    """Look up shared capability revocation state."""

    def is_revoked(self, capability_id: str, at: datetime) -> bool:
        """Return whether the capability was revoked at the decision time."""
        ...


class DelegatedIdentityAuthorizer:
    """Completely mediate agent identity and delegated privilege use."""

    def __init__(
        self,
        policy: DelegatedAccessPolicy,
        *,
        capability_verifier: DelegatedCapabilityVerifier | None = None,
        grant_verifier: DelegatedAccessGrantVerifier | None = None,
        revocation_provider: DelegationRevocationProvider | None = None,
    ) -> None:
        self._policy = policy.model_copy(deep=True)
        self._capability_verifier = capability_verifier
        self._grant_verifier = grant_verifier
        self._revocation_provider = revocation_provider
        self._revocations: dict[str, DelegationRevocation] = {}
        self._used_grant_ids: set[str] = set()
        self._lock = threading.Lock()

    @property
    def policy(self) -> DelegatedAccessPolicy:
        """Return the immutable delegated-access policy."""
        return self._policy.model_copy(deep=True)

    @property
    def revocations(self) -> tuple[DelegationRevocation, ...]:
        """Return process-local revocation records without credential content."""
        with self._lock:
            return tuple(self._revocations.values())

    def revoke(
        self,
        capability_id: str,
        *,
        revoked_by: str,
        reason_code: str,
        now: datetime | None = None,
    ) -> DelegationRevocation:
        """Revoke one capability; chains containing it fail from this time onward."""
        revocation = DelegationRevocation(
            capability_id=capability_id,
            revoked_by=revoked_by,
            reason_code=reason_code,
            revoked_at=now or utcnow(),
        )
        with self._lock:
            existing = self._revocations.get(capability_id)
            if existing is not None and existing.revoked_at <= revocation.revoked_at:
                return existing
            self._revocations[capability_id] = revocation
            return revocation

    def authorize(
        self,
        request: DelegatedAccessRequest,
        *,
        now: datetime | None = None,
    ) -> DelegatedAccessResult:
        """Authorize an exact audience, purpose, scope, and operation request."""
        current_time = now or utcnow()
        findings = self._chain_findings(request.chain, current_time)
        if not request.chain.capabilities:
            return self._blocked(findings)
        findings.extend(self._request_findings(request))
        findings.extend(self._external_revocation_findings(request.chain, current_time))
        grant_findings = self._grant_findings(request, current_time, include_replay=True)
        findings.extend(grant_findings)
        if findings:
            if all(
                finding.code
                in {DelegatedAccessCode.STEP_UP_REQUIRED, DelegatedAccessCode.JIT_ACCESS_REQUIRED}
                for finding in findings
            ):
                return DelegatedAccessResult(
                    action=GuardAction.REQUIRE_APPROVAL,
                    findings=tuple(findings),
                )
            return self._blocked(findings)

        with self._lock:
            mutable_findings = self._mutable_findings(request, current_time)
            if mutable_findings:
                return self._blocked(mutable_findings)
            for grant in request.grants:
                self._used_grant_ids.add(grant.grant_id)

        leaf = request.chain.leaf
        expiry_candidates = [
            leaf.expires_at,
            current_time + timedelta(seconds=self._policy.authorization_ttl_seconds),
            *(grant.expires_at for grant in request.grants),
        ]
        authorization = AuthorizedDelegatedAccess(
            authorization_id=str(uuid.uuid4()),
            request_digest=request.request_digest,
            chain_digest=request.chain.chain_digest,
            capability_id=leaf.capability_id,
            actor_id=leaf.subject.identity_id,
            initiator_id=request.chain.initiator.identity_id,
            tenant_id=request.tenant_id,
            audience=request.audience,
            purpose_id=request.purpose_id,
            operation_id=request.operation_id,
            scopes=request.requested_scopes,
            expires_at=min(expiry_candidates),
        )
        return DelegatedAccessResult(
            action=GuardAction.ALLOW,
            authorization=authorization,
        )

    def require(
        self,
        request: DelegatedAccessRequest,
        *,
        now: datetime | None = None,
    ) -> AuthorizedDelegatedAccess:
        """Return a verified principal snapshot or raise before privileged use."""
        result = self.authorize(request, now=now)
        if not result.is_authorized or result.authorization is None:
            raise DelegatedIdentityError(result=result)
        return result.authorization

    @staticmethod
    def to_tool_principal(
        authorization: AuthorizedDelegatedAccess,
        *,
        now: datetime | None = None,
    ) -> ToolPrincipal:
        """Convert a current delegated authorization into a tool principal."""
        if (now or utcnow()) >= authorization.expires_at:
            raise ValueError("delegated authorization has expired")
        return ToolPrincipal(
            actor_id=authorization.actor_id,
            subject_id=authorization.initiator_id,
            tenant_id=authorization.tenant_id,
            scopes=authorization.scopes,
        )

    def _chain_findings(
        self,
        chain: DelegationChain,
        now: datetime,
    ) -> list[DelegatedAccessFinding]:
        findings: list[DelegatedAccessFinding] = []
        capabilities = chain.capabilities
        if not capabilities:
            return [
                self._finding(
                    DelegatedAccessCode.CHAIN_INTEGRITY_INVALID,
                    Severity.CRITICAL,
                    "Delegation chain must contain a root capability",
                )
            ]
        root = capabilities[0]
        if (
            root.issuer.identity_id not in self._policy.trusted_root_issuer_ids
            or root.issuer.kind not in {AgentIdentityKind.HUMAN, AgentIdentityKind.SERVICE}
        ):
            findings.append(
                self._finding(
                    DelegatedAccessCode.ROOT_ISSUER_UNTRUSTED,
                    Severity.CRITICAL,
                    "Root capability issuer is not trusted by policy",
                )
            )

        for index, capability in enumerate(capabilities):
            if not capability.has_valid_integrity:
                findings.append(
                    self._finding(
                        DelegatedAccessCode.CHAIN_INTEGRITY_INVALID,
                        Severity.CRITICAL,
                        "Capability integrity does not match its security fields",
                    )
                )
            if capability.delegation_depth != index:
                findings.append(
                    self._finding(
                        DelegatedAccessCode.CHAIN_LINK_INVALID,
                        Severity.CRITICAL,
                        "Delegation depths are not contiguous",
                    )
                )
            if (
                capability.delegation_depth > self._policy.max_delegation_depth
                or capability.max_delegation_depth > self._policy.max_delegation_depth
            ):
                findings.append(
                    self._finding(
                        DelegatedAccessCode.DELEGATION_DEPTH_EXCEEDED,
                        Severity.CRITICAL,
                        "Capability exceeds the policy delegation depth",
                    )
                )
            lifetime = (capability.expires_at - capability.issued_at).total_seconds()
            if lifetime > self._policy.max_capability_lifetime_seconds:
                findings.append(
                    self._finding(
                        DelegatedAccessCode.CAPABILITY_LIFETIME_EXCEEDED,
                        Severity.HIGH,
                        "Capability lifetime exceeds policy",
                    )
                )
            if now < capability.not_before:
                findings.append(
                    self._finding(
                        DelegatedAccessCode.CAPABILITY_NOT_YET_VALID,
                        Severity.HIGH,
                        "Capability is not valid yet",
                    )
                )
            if now >= capability.expires_at:
                findings.append(
                    self._finding(
                        DelegatedAccessCode.CAPABILITY_EXPIRED,
                        Severity.HIGH,
                        "Capability has expired",
                    )
                )
            if not self._verify_capability(capability):
                findings.append(
                    self._finding(
                        DelegatedAccessCode.CAPABILITY_INVALID,
                        Severity.CRITICAL,
                        "Capability authenticity could not be verified",
                    )
                )
            if index > 0:
                findings.extend(self._chain_link_findings(capabilities[index - 1], capability))

        with self._lock:
            findings.extend(self._local_revocation_findings(chain, now))
        return findings

    def _chain_link_findings(
        self,
        parent: DelegatedCapability,
        child: DelegatedCapability,
    ) -> list[DelegatedAccessFinding]:
        common_invalid = (
            child.parent_capability_id != parent.capability_id
            or child.parent_capability_digest != parent.capability_digest
            or child.issuer != parent.subject
            or child.subject.tenant_id != parent.subject.tenant_id
            or not child.audiences.issubset(parent.audiences)
            or child.purpose_id != parent.purpose_id
            or child.issued_at < parent.issued_at
            or child.not_before < parent.not_before
            or child.expires_at > parent.expires_at
            or child.max_delegation_depth > parent.max_delegation_depth
        )
        findings: list[DelegatedAccessFinding] = []
        if common_invalid:
            findings.append(
                self._finding(
                    DelegatedAccessCode.CHAIN_LINK_INVALID,
                    Severity.CRITICAL,
                    "Delegated capability is not an exact narrowing of its parent",
                )
            )
        if not child.scopes.issubset(parent.delegatable_scopes):
            findings.append(
                self._finding(
                    DelegatedAccessCode.PRIVILEGE_AMPLIFICATION,
                    Severity.CRITICAL,
                    "Delegated scopes exceed the parent's delegatable privileges",
                )
            )
        return findings

    def _request_findings(
        self,
        request: DelegatedAccessRequest,
    ) -> list[DelegatedAccessFinding]:
        leaf = request.chain.leaf
        findings: list[DelegatedAccessFinding] = []
        if request.presenter != leaf.subject:
            findings.append(
                self._finding(
                    DelegatedAccessCode.PRESENTER_MISMATCH,
                    Severity.CRITICAL,
                    "Capability was forwarded to or presented by another identity",
                )
            )
        if request.tenant_id != leaf.subject.tenant_id or any(
            capability.issuer.tenant_id != request.tenant_id
            or capability.subject.tenant_id != request.tenant_id
            for capability in request.chain.capabilities
        ):
            findings.append(
                self._finding(
                    DelegatedAccessCode.TENANT_MISMATCH,
                    Severity.CRITICAL,
                    "Delegated access crosses a tenant boundary",
                )
            )
        if (
            request.audience not in self._policy.allowed_audiences
            or request.audience not in leaf.audiences
        ):
            findings.append(
                self._finding(
                    DelegatedAccessCode.AUDIENCE_DENIED,
                    Severity.CRITICAL,
                    "Capability audience does not match the target service or tool",
                )
            )
        if request.purpose_id != leaf.purpose_id:
            findings.append(
                self._finding(
                    DelegatedAccessCode.PURPOSE_MISMATCH,
                    Severity.CRITICAL,
                    "Capability purpose does not match the proposed operation",
                )
            )
        if not request.requested_scopes.issubset(leaf.scopes):
            findings.append(
                self._finding(
                    DelegatedAccessCode.SCOPE_DENIED,
                    Severity.CRITICAL,
                    "Requested privileges exceed the leaf capability",
                )
            )
        return findings

    def _grant_findings(
        self,
        request: DelegatedAccessRequest,
        now: datetime,
        *,
        include_replay: bool,
    ) -> list[DelegatedAccessFinding]:
        step_up_scopes = request.requested_scopes.intersection(self._policy.step_up_required_scopes)
        jit_scopes = request.requested_scopes.intersection(self._policy.jit_required_scopes)
        required = {
            DelegatedAccessGrantKind.STEP_UP: (
                step_up_scopes,
                DelegatedAccessCode.STEP_UP_REQUIRED,
            ),
            DelegatedAccessGrantKind.JUST_IN_TIME: (
                jit_scopes,
                DelegatedAccessCode.JIT_ACCESS_REQUIRED,
            ),
        }
        grants = {grant.kind: grant for grant in request.grants}
        findings: list[DelegatedAccessFinding] = []
        for kind, (scopes, required_code) in required.items():
            grant = grants.get(kind)
            if scopes and grant is None:
                findings.append(
                    self._finding(
                        required_code,
                        Severity.HIGH,
                        "An out-of-band privilege elevation is required",
                    )
                )
                continue
            if not scopes and grant is not None:
                findings.append(
                    self._finding(
                        DelegatedAccessCode.GRANT_INVALID,
                        Severity.HIGH,
                        "Privilege grant was supplied for an operation that does not require it",
                    )
                )
                continue
            if grant is None:
                continue
            findings.extend(
                self._validate_grant(
                    request,
                    grant,
                    scopes,
                    now,
                    include_replay=include_replay,
                )
            )
        return findings

    def _validate_grant(
        self,
        request: DelegatedAccessRequest,
        grant: DelegatedAccessGrant,
        required_scopes: frozenset[str],
        now: datetime,
        *,
        include_replay: bool,
    ) -> list[DelegatedAccessFinding]:
        findings: list[DelegatedAccessFinding] = []
        invalid_binding = (
            grant.request_digest != request.request_digest
            or grant.subject_id != request.presenter.identity_id
            or grant.tenant_id != request.tenant_id
            or grant.approved_scopes != required_scopes
            or grant.issued_at > now
            or (grant.expires_at - grant.issued_at).total_seconds()
            > self._policy.max_grant_lifetime_seconds
            or (
                grant.kind == DelegatedAccessGrantKind.STEP_UP
                and grant.assurance_level < self._policy.minimum_step_up_assurance
            )
        )
        if invalid_binding or not self._verify_grant(grant):
            findings.append(
                self._finding(
                    DelegatedAccessCode.GRANT_INVALID,
                    Severity.CRITICAL,
                    "Privilege grant is not valid for this exact request",
                )
            )
        if now >= grant.expires_at:
            findings.append(
                self._finding(
                    DelegatedAccessCode.GRANT_EXPIRED,
                    Severity.HIGH,
                    "Privilege grant has expired",
                )
            )
        if include_replay:
            with self._lock:
                replayed = grant.grant_id in self._used_grant_ids
            if replayed:
                findings.append(
                    self._finding(
                        DelegatedAccessCode.GRANT_REPLAYED,
                        Severity.CRITICAL,
                        "Privilege grant has already been consumed",
                    )
                )
        return findings

    def _mutable_findings(
        self,
        request: DelegatedAccessRequest,
        now: datetime,
    ) -> list[DelegatedAccessFinding]:
        findings = self._local_revocation_findings(request.chain, now)
        findings.extend(self._grant_findings_without_lock(request))
        return findings

    def _grant_findings_without_lock(
        self,
        request: DelegatedAccessRequest,
    ) -> list[DelegatedAccessFinding]:
        return [
            self._finding(
                DelegatedAccessCode.GRANT_REPLAYED,
                Severity.CRITICAL,
                "Privilege grant has already been consumed",
            )
            for grant in request.grants
            if grant.grant_id in self._used_grant_ids
        ]

    def _local_revocation_findings(
        self,
        chain: DelegationChain,
        now: datetime,
    ) -> list[DelegatedAccessFinding]:
        return [
            self._finding(
                DelegatedAccessCode.CAPABILITY_REVOKED,
                Severity.CRITICAL,
                "Delegation chain contains a revoked capability",
            )
            for capability in chain.capabilities
            if (
                (revocation := self._revocations.get(capability.capability_id)) is not None
                and revocation.revoked_at <= now
            )
        ][:1]

    def _external_revocation_findings(
        self,
        chain: DelegationChain,
        now: datetime,
    ) -> list[DelegatedAccessFinding]:
        if self._revocation_provider is None:
            return []
        try:
            revoked = any(
                self._revocation_provider.is_revoked(capability.capability_id, now)
                for capability in chain.capabilities
            )
        except Exception:
            return [
                self._finding(
                    DelegatedAccessCode.CAPABILITY_STATUS_UNAVAILABLE,
                    Severity.CRITICAL,
                    "Shared capability revocation status is unavailable",
                )
            ]
        if not revoked:
            return []
        return [
            self._finding(
                DelegatedAccessCode.CAPABILITY_REVOKED,
                Severity.CRITICAL,
                "Delegation chain contains a revoked capability",
            )
        ]

    def _verify_capability(self, capability: DelegatedCapability) -> bool:
        if self._capability_verifier is None:
            return False
        try:
            return self._capability_verifier.verify_capability(capability)
        except Exception:
            return False

    def _verify_grant(self, grant: DelegatedAccessGrant) -> bool:
        if self._grant_verifier is None:
            return False
        try:
            return self._grant_verifier.verify_grant(grant)
        except Exception:
            return False

    @staticmethod
    def _blocked(findings: list[DelegatedAccessFinding]) -> DelegatedAccessResult:
        return DelegatedAccessResult(action=GuardAction.BLOCK, findings=tuple(findings))

    @staticmethod
    def _finding(
        code: DelegatedAccessCode,
        severity: Severity,
        message: str,
    ) -> DelegatedAccessFinding:
        return DelegatedAccessFinding(code=code, severity=severity, message=message)


class StaticDelegatedCapabilityVerifier:
    """Test/example verifier backed by trusted capability IDs and digests."""

    def __init__(self, valid_capabilities: frozenset[tuple[str, str]]) -> None:
        self._valid_capabilities = valid_capabilities

    def verify_capability(self, capability: DelegatedCapability) -> bool:
        return (capability.capability_id, capability.capability_digest) in self._valid_capabilities


class StaticDelegatedAccessGrantVerifier:
    """Test/example verifier backed by trusted grant IDs."""

    def __init__(self, valid_grant_ids: frozenset[str]) -> None:
        self._valid_grant_ids = valid_grant_ids

    def verify_grant(self, grant: DelegatedAccessGrant) -> bool:
        return grant.grant_id in self._valid_grant_ids
