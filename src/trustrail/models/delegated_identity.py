"""Typed identity and delegated-privilege models for agent workloads."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"


def _digest(payload: Any) -> str:
    canonical = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class AgentIdentityKind(StrEnum):
    """Authenticated identity classes that may participate in delegation."""

    HUMAN = "human"
    SERVICE = "service"
    AGENT = "agent"
    SUB_AGENT = "sub_agent"


class AgentIdentity(BaseModel):
    """Immutable workload or initiating-user identity from trusted authentication."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    identity_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    kind: AgentIdentityKind
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)


class DelegatedCapability(BaseModel):
    """Integrity-bound, short-lived authority delegated to one exact identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issuer: AgentIdentity
    subject: AgentIdentity
    scopes: frozenset[str] = Field(min_length=1, max_length=1_000)
    delegatable_scopes: frozenset[str] = Field(default_factory=frozenset, max_length=1_000)
    audiences: frozenset[str] = Field(min_length=1, max_length=1_000)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    delegation_depth: int = Field(ge=0, le=100)
    max_delegation_depth: int = Field(ge=0, le=100)
    parent_capability_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    parent_capability_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    capability_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issued_at", "not_before", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_capability(self) -> DelegatedCapability:
        if self.issuer.tenant_id != self.subject.tenant_id:
            raise ValueError("capability issuer and subject must share a tenant")
        if not self.delegatable_scopes.issubset(self.scopes):
            raise ValueError("delegatable_scopes must be a subset of scopes")
        if self.not_before < self.issued_at:
            raise ValueError("not_before must not precede issued_at")
        if self.expires_at <= self.not_before:
            raise ValueError("expires_at must be after not_before")
        if self.delegation_depth > self.max_delegation_depth:
            raise ValueError("delegation depth exceeds the capability maximum")
        parent_fields = (self.parent_capability_id, self.parent_capability_digest)
        if self.delegation_depth == 0 and any(field is not None for field in parent_fields):
            raise ValueError("root capabilities must not reference a parent")
        if self.delegation_depth > 0 and any(field is None for field in parent_fields):
            raise ValueError("delegated capabilities must bind their parent")
        if not self.has_valid_integrity:
            raise ValueError("capability integrity check failed")
        return self

    @classmethod
    def create(
        cls,
        *,
        capability_id: str,
        issuer: AgentIdentity,
        subject: AgentIdentity,
        scopes: frozenset[str],
        audiences: frozenset[str],
        purpose_id: str,
        issued_at: datetime,
        not_before: datetime,
        expires_at: datetime,
        delegation_depth: int = 0,
        max_delegation_depth: int = 0,
        delegatable_scopes: frozenset[str] = frozenset(),
        parent: DelegatedCapability | None = None,
    ) -> DelegatedCapability:
        """Create a capability with a canonical integrity digest."""
        parent_id = parent.capability_id if parent else None
        parent_digest = parent.capability_digest if parent else None
        payload = cls._digest_payload(
            capability_id=capability_id,
            issuer=issuer,
            subject=subject,
            scopes=scopes,
            delegatable_scopes=delegatable_scopes,
            audiences=audiences,
            purpose_id=purpose_id,
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
            delegation_depth=delegation_depth,
            max_delegation_depth=max_delegation_depth,
            parent_capability_id=parent_id,
            parent_capability_digest=parent_digest,
        )
        return cls(
            capability_id=capability_id,
            issuer=issuer,
            subject=subject,
            scopes=scopes,
            delegatable_scopes=delegatable_scopes,
            audiences=audiences,
            purpose_id=purpose_id,
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
            delegation_depth=delegation_depth,
            max_delegation_depth=max_delegation_depth,
            parent_capability_id=parent_id,
            parent_capability_digest=parent_digest,
            capability_digest=_digest(payload),
        )

    @property
    def has_valid_integrity(self) -> bool:
        """Return whether every security-relevant field matches the digest."""
        payload = self._digest_payload(
            capability_id=self.capability_id,
            issuer=self.issuer,
            subject=self.subject,
            scopes=self.scopes,
            delegatable_scopes=self.delegatable_scopes,
            audiences=self.audiences,
            purpose_id=self.purpose_id,
            issued_at=self.issued_at,
            not_before=self.not_before,
            expires_at=self.expires_at,
            delegation_depth=self.delegation_depth,
            max_delegation_depth=self.max_delegation_depth,
            parent_capability_id=self.parent_capability_id,
            parent_capability_digest=self.parent_capability_digest,
        )
        return self.capability_digest == _digest(payload)

    @staticmethod
    def _digest_payload(
        *,
        capability_id: str,
        issuer: AgentIdentity,
        subject: AgentIdentity,
        scopes: frozenset[str],
        delegatable_scopes: frozenset[str],
        audiences: frozenset[str],
        purpose_id: str,
        issued_at: datetime,
        not_before: datetime,
        expires_at: datetime,
        delegation_depth: int,
        max_delegation_depth: int,
        parent_capability_id: str | None,
        parent_capability_digest: str | None,
    ) -> dict[str, Any]:
        return {
            "audiences": sorted(audiences),
            "capability_id": capability_id,
            "delegatable_scopes": sorted(delegatable_scopes),
            "delegation_depth": delegation_depth,
            "expires_at": expires_at.isoformat(),
            "issued_at": issued_at.isoformat(),
            "issuer": issuer.model_dump(mode="json"),
            "max_delegation_depth": max_delegation_depth,
            "not_before": not_before.isoformat(),
            "parent_capability_digest": parent_capability_digest,
            "parent_capability_id": parent_capability_id,
            "purpose_id": purpose_id,
            "scopes": sorted(scopes),
            "subject": subject.model_dump(mode="json"),
        }


class DelegationChain(BaseModel):
    """Ordered immutable authority lineage from initiator to presenting agent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capabilities: tuple[DelegatedCapability, ...] = Field(min_length=1, max_length=101)

    @model_validator(mode="after")
    def validate_chain(self) -> DelegationChain:
        for index, capability in enumerate(self.capabilities):
            if capability.delegation_depth != index:
                raise ValueError("capability depths must be contiguous and start at zero")
            if index == 0:
                continue
            parent = self.capabilities[index - 1]
            if capability.parent_capability_id != parent.capability_id:
                raise ValueError("delegated capability references the wrong parent ID")
            if capability.parent_capability_digest != parent.capability_digest:
                raise ValueError("delegated capability references the wrong parent digest")
            if capability.issuer != parent.subject:
                raise ValueError("delegated capability issuer must be the parent subject")
            if capability.subject.tenant_id != parent.subject.tenant_id:
                raise ValueError("delegation cannot cross tenants")
            if not capability.scopes.issubset(parent.delegatable_scopes):
                raise ValueError("delegated scopes exceed the parent grant")
            if not capability.audiences.issubset(parent.audiences):
                raise ValueError("delegated audiences exceed the parent grant")
            if capability.purpose_id != parent.purpose_id:
                raise ValueError("delegation cannot change purpose")
            if capability.issued_at < parent.issued_at:
                raise ValueError("delegated capability cannot predate its parent")
            if capability.not_before < parent.not_before:
                raise ValueError("delegated activation cannot predate its parent")
            if capability.expires_at > parent.expires_at:
                raise ValueError("delegated capability cannot outlive its parent")
            if capability.max_delegation_depth > parent.max_delegation_depth:
                raise ValueError("delegated capability cannot expand maximum depth")
        return self

    @property
    def root(self) -> DelegatedCapability:
        return self.capabilities[0]

    @property
    def leaf(self) -> DelegatedCapability:
        return self.capabilities[-1]

    @property
    def initiator(self) -> AgentIdentity:
        return self.root.issuer

    @property
    def chain_digest(self) -> str:
        """Return a stable fingerprint for the complete delegation lineage."""
        return _digest([capability.capability_digest for capability in self.capabilities])


class DelegatedAccessGrantKind(StrEnum):
    """Out-of-band controls that activate high-impact delegated scopes."""

    STEP_UP = "step_up"
    JUST_IN_TIME = "just_in_time"


class DelegatedAccessGrant(BaseModel):
    """Short-lived, single-use step-up or just-in-time authorization grant."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    kind: DelegatedAccessGrantKind
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    subject_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    approved_scopes: frozenset[str] = Field(min_length=1, max_length=1_000)
    assurance_level: int = Field(default=0, ge=0, le=4)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_window(self) -> DelegatedAccessGrant:
        if self.expires_at <= self.issued_at:
            raise ValueError("grant expires_at must be after issued_at")
        return self


class DelegatedAccessPolicy(BaseModel):
    """Fail-closed identity and privilege-lifecycle policy for agents."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trusted_root_issuer_ids: frozenset[str] = Field(min_length=1, max_length=10_000)
    allowed_audiences: frozenset[str] = Field(min_length=1, max_length=10_000)
    max_capability_lifetime_seconds: int = Field(default=900, ge=1, le=86_400)
    max_grant_lifetime_seconds: int = Field(default=300, ge=1, le=3_600)
    max_delegation_depth: int = Field(default=3, ge=0, le=100)
    authorization_ttl_seconds: int = Field(default=60, ge=1, le=3_600)
    step_up_required_scopes: frozenset[str] = Field(default_factory=frozenset)
    jit_required_scopes: frozenset[str] = Field(default_factory=frozenset)
    minimum_step_up_assurance: int = Field(default=2, ge=1, le=4)


class DelegatedAccessRequest(BaseModel):
    """One privileged operation proposed under an authenticated delegation chain."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    presenter: AgentIdentity
    chain: DelegationChain
    audience: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    requested_scopes: frozenset[str] = Field(min_length=1, max_length=1_000)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    operation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    grants: tuple[DelegatedAccessGrant, ...] = Field(default_factory=tuple, max_length=2)

    @model_validator(mode="after")
    def validate_grant_uniqueness(self) -> DelegatedAccessRequest:
        grant_ids = [grant.grant_id for grant in self.grants]
        grant_kinds = [grant.kind for grant in self.grants]
        if len(grant_ids) != len(set(grant_ids)):
            raise ValueError("access grant IDs must be unique")
        if len(grant_kinds) != len(set(grant_kinds)):
            raise ValueError("only one grant of each kind is allowed")
        return self

    @property
    def request_digest(self) -> str:
        """Bind step-up and JIT grants to this exact operation and lineage."""
        return _digest(
            {
                "audience": self.audience,
                "chain_digest": self.chain.chain_digest,
                "operation_id": self.operation_id,
                "presenter": self.presenter.model_dump(mode="json"),
                "purpose_id": self.purpose_id,
                "requested_scopes": sorted(self.requested_scopes),
                "tenant_id": self.tenant_id,
            }
        )


class DelegatedAccessCode(StrEnum):
    """Stable machine-readable delegated identity outcomes."""

    CHAIN_INTEGRITY_INVALID = "chain_integrity_invalid"
    CHAIN_LINK_INVALID = "chain_link_invalid"
    ROOT_ISSUER_UNTRUSTED = "root_issuer_untrusted"
    CAPABILITY_INVALID = "capability_invalid"
    CAPABILITY_NOT_YET_VALID = "capability_not_yet_valid"
    CAPABILITY_EXPIRED = "capability_expired"
    CAPABILITY_LIFETIME_EXCEEDED = "capability_lifetime_exceeded"
    CAPABILITY_REVOKED = "capability_revoked"
    CAPABILITY_STATUS_UNAVAILABLE = "capability_status_unavailable"
    DELEGATION_DEPTH_EXCEEDED = "delegation_depth_exceeded"
    PRESENTER_MISMATCH = "presenter_mismatch"
    TENANT_MISMATCH = "tenant_mismatch"
    AUDIENCE_DENIED = "audience_denied"
    PURPOSE_MISMATCH = "purpose_mismatch"
    SCOPE_DENIED = "scope_denied"
    PRIVILEGE_AMPLIFICATION = "privilege_amplification"
    STEP_UP_REQUIRED = "step_up_required"
    JIT_ACCESS_REQUIRED = "jit_access_required"
    GRANT_INVALID = "grant_invalid"
    GRANT_EXPIRED = "grant_expired"
    GRANT_REPLAYED = "grant_replayed"


class DelegatedAccessFinding(BaseModel):
    """Content-free explanation for an identity authorization decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: DelegatedAccessCode
    severity: Severity
    message: str


class AuthorizedDelegatedAccess(BaseModel):
    """Short-lived verified principal snapshot for one exact operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    chain_digest: str = Field(pattern=_DIGEST_PATTERN)
    capability_id: str
    actor_id: str
    initiator_id: str
    tenant_id: str
    audience: str
    purpose_id: str
    operation_id: str
    scopes: frozenset[str]
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def require_aware_expiry(cls, value: datetime) -> datetime:
        return _require_aware(value, "expires_at")


class DelegatedAccessResult(BaseModel):
    """Allow, block, or step-up/JIT decision for delegated access."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK, GuardAction.REQUIRE_APPROVAL]
    findings: tuple[DelegatedAccessFinding, ...] = ()
    authorization: AuthorizedDelegatedAccess | None = None

    @property
    def is_authorized(self) -> bool:
        return self.action == GuardAction.ALLOW and self.authorization is not None

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK

    @property
    def requires_elevation(self) -> bool:
        return self.action == GuardAction.REQUIRE_APPROVAL


class DelegationRevocation(BaseModel):
    """Application-owned revocation record for one capability and descendants."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    revoked_by: str = Field(pattern=_IDENTIFIER_PATTERN)
    reason_code: str = Field(pattern=_IDENTIFIER_PATTERN)
    revoked_at: datetime

    @field_validator("revoked_at")
    @classmethod
    def require_aware_revocation(cls, value: datetime) -> datetime:
        return _require_aware(value, "revoked_at")


def utcnow() -> datetime:
    """Return an aware timestamp; isolated for deterministic testing."""
    return datetime.now(tz=UTC)
