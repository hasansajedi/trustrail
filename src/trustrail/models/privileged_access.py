"""Typed contracts for step-up authentication and JIT AI privileges."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.data_labels import canonical_data_label_json
from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_REFERENCE_PATTERN = r"^sha256:[0-9a-f]{64}$"


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def privileged_access_digest(value: Any) -> str:
    """Return a deterministic SHA-256 digest for privileged access metadata."""
    return hashlib.sha256(canonical_data_label_json(value).encode()).hexdigest()


def privileged_access_reference(value: str | bytes) -> str:
    """Return a one-way identifier for decisions and audit evidence."""
    raw = value.encode() if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class PrivilegedAIOperation(StrEnum):
    """High-risk AI platform operations requiring zero standing privilege."""

    MODEL_DEPLOY = "model_deploy"
    MODEL_WEIGHT_EXPORT = "model_weight_export"
    TRAINING_DATA_READ = "training_data_read"
    TRAINING_PIPELINE_MODIFY = "training_pipeline_modify"
    PRODUCTION_PROMPT_MODIFY = "production_prompt_modify"
    SAFETY_POLICY_MODIFY = "safety_policy_modify"
    PRODUCTION_CONFIG_MODIFY = "production_config_modify"


class AuthenticationAssurance(IntEnum):
    """Application-defined authentication assurance ordered by strength."""

    BASIC = 1
    MULTI_FACTOR = 2
    PHISHING_RESISTANT = 3
    HARDWARE_BOUND = 4


class PrivilegedAccessPhase(StrEnum):
    """Lifecycle phase mediated by the privileged access manager."""

    ISSUE = "issue"
    EXECUTE = "execute"
    REVOKE = "revoke"


class PrivilegeGrantStateStatus(StrEnum):
    """Atomic lifecycle result returned by a JIT grant state store."""

    STORED = "stored"
    COLLISION = "collision"
    CONSUMED = "consumed"
    REPLAYED = "replayed"
    REVOKED = "revoked"
    MISSING = "missing"
    EXPIRED = "expired"


class PrivilegedAccessCode(StrEnum):
    """Stable machine-readable privileged-access outcomes."""

    ALLOWED = "allowed"
    OPERATION_NOT_CLASSIFIED = "operation_not_classified"
    POLICY_MISMATCH = "policy_mismatch"
    ACTOR_CONTEXT_MISMATCH = "actor_context_mismatch"
    IDENTITY_INACTIVE = "identity_inactive"
    IDENTITY_SERVICE_UNAVAILABLE = "identity_service_unavailable"
    ROLE_DENIED = "role_denied"
    SESSION_EXPIRED = "session_expired"
    SESSION_DURATION_EXCEEDED = "session_duration_exceeded"
    SCOPE_DENIED = "scope_denied"
    STEP_UP_REQUIRED = "step_up_required"
    STEP_UP_INVALID = "step_up_invalid"
    STEP_UP_EXPIRED = "step_up_expired"
    STEP_UP_SERVICE_UNAVAILABLE = "step_up_service_unavailable"
    ASSURANCE_INSUFFICIENT = "assurance_insufficient"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    APPROVER_NOT_INDEPENDENT = "approver_not_independent"
    APPROVAL_SERVICE_UNAVAILABLE = "approval_service_unavailable"
    RISK_DENIED = "risk_denied"
    RISK_SERVICE_UNAVAILABLE = "risk_service_unavailable"
    BACKEND_AUTHORIZATION_DENIED = "backend_authorization_denied"
    AUTHORIZATION_SERVICE_UNAVAILABLE = "authorization_service_unavailable"
    GRANT_INVALID = "grant_invalid"
    GRANT_EXPIRED = "grant_expired"
    GRANT_REPLAYED = "grant_replayed"
    GRANT_REVOKED = "grant_revoked"
    GRANT_STATE_UNAVAILABLE = "grant_state_unavailable"
    IDENTITY_CHANGED = "identity_changed"
    ROLE_CHANGED = "role_changed"
    POLICY_CHANGED = "policy_changed"
    RISK_CHANGED = "risk_changed"
    SESSION_CHANGED = "session_changed"


class PrivilegedOperationPolicy(BaseModel):
    """Step-up and zero-standing-privilege requirements for one operation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation: PrivilegedAIOperation
    required_scopes: frozenset[str] = Field(min_length=1, max_length=1_000)
    eligible_role_ids: frozenset[str] = Field(min_length=1, max_length=1_000)
    minimum_assurance: AuthenticationAssurance
    require_independent_approval: bool = True
    allowed_approver_ids: frozenset[str] = Field(default_factory=frozenset, max_length=10_000)
    maximum_session_duration_seconds: int = Field(ge=1, le=86_400)
    maximum_step_up_age_seconds: int = Field(default=300, ge=1, le=3_600)
    maximum_grant_ttl_seconds: int = Field(default=60, ge=1, le=900)
    maximum_risk_score: int = Field(default=30, ge=0, le=100)

    @model_validator(mode="after")
    def validate_approval_policy(self) -> PrivilegedOperationPolicy:
        if self.require_independent_approval and not self.allowed_approver_ids:
            raise ValueError("independent approval requires allowed approver IDs")
        if not self.require_independent_approval and self.allowed_approver_ids:
            raise ValueError("approver IDs require independent approval")
        return self


class PrivilegedAccessPolicy(BaseModel):
    """Versioned classification policy for high-risk AI operations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    version: int = Field(ge=1)
    operations: tuple[PrivilegedOperationPolicy, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_operations(self) -> PrivilegedAccessPolicy:
        operation_ids = [item.operation for item in self.operations]
        if len(operation_ids) != len(set(operation_ids)):
            raise ValueError("privileged operation policies must be unique")
        return self

    def policy_for(self, operation: PrivilegedAIOperation) -> PrivilegedOperationPolicy | None:
        """Return the classification for an operation, or ``None`` to deny it."""
        return next((item for item in self.operations if item.operation == operation), None)

    @property
    def policy_digest(self) -> str:
        return privileged_access_digest(self.model_dump(mode="python"))


class PrivilegedActorContext(BaseModel):
    """Caller assertions that must be reconciled with the identity service."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    actor_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    identity_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    role_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    risk_version: str = Field(pattern=_IDENTIFIER_PATTERN)


class PrivilegedIdentitySnapshot(BaseModel):
    """Current identity, role, and session state from a trusted authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    actor_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    identity_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    role_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    role_ids: frozenset[str] = Field(min_length=1, max_length=1_000)
    active: bool
    session_started_at: datetime
    session_expires_at: datetime

    @field_validator("session_started_at", "session_expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_session(self) -> PrivilegedIdentitySnapshot:
        if self.session_expires_at <= self.session_started_at:
            raise ValueError("session_expires_at must be after session_started_at")
        return self


class PrivilegedRiskSnapshot(BaseModel):
    """Current risk posture for an exact actor session."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    actor_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    risk_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    score: int = Field(ge=0, le=100)
    blocked: bool = False
    assessed_at: datetime
    expires_at: datetime

    @field_validator("assessed_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> PrivilegedRiskSnapshot:
        if self.expires_at <= self.assessed_at:
            raise ValueError("risk expires_at must be after assessed_at")
        return self


class PrivilegedActionRequest(BaseModel):
    """One exact high-risk AI action requiring fresh authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    actor: PrivilegedActorContext
    operation: PrivilegedAIOperation
    target_id: str = Field(min_length=1, max_length=4_096)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    requested_scopes: frozenset[str] = Field(min_length=1, max_length=1_000)
    policy_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    policy_version: int = Field(ge=1)
    policy_digest: str = Field(pattern=_DIGEST_PATTERN)
    nonce: str = Field(pattern=_IDENTIFIER_PATTERN)

    @property
    def target_ref(self) -> str:
        return privileged_access_reference(self.target_id)

    @property
    def request_digest(self) -> str:
        return privileged_access_digest(
            {
                "actor": self.actor.model_dump(mode="python"),
                "nonce": self.nonce,
                "operation": self.operation,
                "policy_digest": self.policy_digest,
                "policy_id": self.policy_id,
                "policy_version": self.policy_version,
                "purpose_id": self.purpose_id,
                "requested_scopes": self.requested_scopes,
                "target_ref": self.target_ref,
            }
        )


class StepUpAuthenticationEvidence(BaseModel):
    """Fresh authenticated evidence bound to one exact privileged request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    actor_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    policy_digest: str = Field(pattern=_DIGEST_PATTERN)
    nonce: str = Field(pattern=_IDENTIFIER_PATTERN)
    assurance: AuthenticationAssurance
    authentication_methods: frozenset[str] = Field(min_length=1, max_length=100)
    authenticated_at: datetime
    expires_at: datetime

    @field_validator("authenticated_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> StepUpAuthenticationEvidence:
        if self.expires_at <= self.authenticated_at:
            raise ValueError("step-up expires_at must be after authenticated_at")
        return self

    @property
    def evidence_digest(self) -> str:
        return privileged_access_digest(self.model_dump(mode="python"))


class PrivilegedApprovalEvidence(BaseModel):
    """Independent approval bound to one exact privileged request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    actor_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    approver_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    policy_digest: str = Field(pattern=_DIGEST_PATTERN)
    nonce: str = Field(pattern=_IDENTIFIER_PATTERN)
    approved_at: datetime
    expires_at: datetime

    @field_validator("approved_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> PrivilegedApprovalEvidence:
        if self.expires_at <= self.approved_at:
            raise ValueError("approval expires_at must be after approved_at")
        return self

    @property
    def approval_digest(self) -> str:
        return privileged_access_digest(self.model_dump(mode="python"))


class BackendAuthorizationDecision(BaseModel):
    """Current decision from the authoritative resource backend."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    allowed: bool
    authorization_revision: str = Field(pattern=_IDENTIFIER_PATTERN)
    reason_code: str = Field(pattern=_IDENTIFIER_PATTERN)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime) -> datetime:
        return _require_aware(value, "expires_at")


class JITPrivilegeGrant(BaseModel):
    """Narrow, short-lived, single-use activation of one privileged action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    actor_ref: str = Field(pattern=_REFERENCE_PATTERN)
    tenant_ref: str = Field(pattern=_REFERENCE_PATTERN)
    session_ref: str = Field(pattern=_REFERENCE_PATTERN)
    operation: PrivilegedAIOperation
    target_ref: str = Field(pattern=_REFERENCE_PATTERN)
    scopes: frozenset[str] = Field(min_length=1, max_length=1_000)
    policy_digest: str = Field(pattern=_DIGEST_PATTERN)
    identity_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    role_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    risk_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    step_up_evidence_digest: str = Field(pattern=_DIGEST_PATTERN)
    approval_evidence_digest: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    issued_at: datetime
    expires_at: datetime
    grant_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_grant(self) -> JITPrivilegeGrant:
        if self.expires_at <= self.issued_at:
            raise ValueError("grant expires_at must be after issued_at")
        if not self.has_valid_integrity:
            raise ValueError("grant integrity check failed")
        return self

    @classmethod
    def create(cls, **values: Any) -> JITPrivilegeGrant:
        candidate = cls.model_construct(**values, grant_digest="0" * 64)
        payload = candidate.model_dump(mode="python", exclude={"grant_digest"})
        return cls(**payload, grant_digest=privileged_access_digest(payload))

    @property
    def has_valid_integrity(self) -> bool:
        payload = self.model_dump(mode="python", exclude={"grant_digest"})
        return self.grant_digest == privileged_access_digest(payload)


class AuthorizedPrivilegedOperation(BaseModel):
    """Exact execution permit requiring a backend revision check."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(pattern=_DIGEST_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    grant_digest: str = Field(pattern=_DIGEST_PATTERN)
    actor_ref: str = Field(pattern=_REFERENCE_PATTERN)
    tenant_ref: str = Field(pattern=_REFERENCE_PATTERN)
    operation: PrivilegedAIOperation
    target_ref: str = Field(pattern=_REFERENCE_PATTERN)
    scopes: frozenset[str] = Field(min_length=1)
    backend_authorization_revision: str = Field(pattern=_IDENTIFIER_PATTERN)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime) -> datetime:
        return _require_aware(value, "expires_at")


class PrivilegedAccessFinding(BaseModel):
    """Content-free explanation for a privileged access decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: PrivilegedAccessCode
    severity: Severity
    message: str


class PrivilegedAccessAuditEvent(BaseModel):
    """Content-free audit evidence for issue, execute, and revoke phases."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    occurred_at: datetime
    phase: PrivilegedAccessPhase
    action: GuardAction
    code: PrivilegedAccessCode
    request_ref: str = Field(pattern=_REFERENCE_PATTERN)
    actor_ref: str = Field(pattern=_REFERENCE_PATTERN)
    tenant_ref: str = Field(pattern=_REFERENCE_PATTERN)
    target_ref: str = Field(pattern=_REFERENCE_PATTERN)
    operation: PrivilegedAIOperation
    grant_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)


class PrivilegedAccessDecision(BaseModel):
    """Fail-closed result for grant issuance or privileged execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK, GuardAction.REQUIRE_APPROVAL]
    findings: tuple[PrivilegedAccessFinding, ...] = ()
    grant: JITPrivilegeGrant | None = None
    authorization: AuthorizedPrivilegedOperation | None = None
    audit_event: PrivilegedAccessAuditEvent

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW

    @property
    def requires_step_up(self) -> bool:
        return self.action == GuardAction.REQUIRE_APPROVAL
