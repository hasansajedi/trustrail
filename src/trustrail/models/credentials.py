"""Typed contracts for model-blind credential brokering."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_REFERENCE_PATTERN = r"^credref_[A-Za-z0-9_-]{16,128}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def credential_digest(value: Any) -> str:
    """Return a deterministic digest for credential-control metadata."""
    canonical = json.dumps(
        value,
        allow_nan=False,
        default=str,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def credential_reference(value: str | bytes) -> str:
    """Return a one-way identifier suitable for audit evidence."""
    raw = value.encode() if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class CredentialSurface(StrEnum):
    """A boundary that must never receive raw credential material."""

    PROMPT = "prompt"
    MODEL_OUTPUT = "model_output"
    TOOL_SCHEMA = "tool_schema"
    TOOL_ARGUMENTS = "tool_arguments"
    APPROVAL = "approval"
    MEMORY = "memory"
    TELEMETRY = "telemetry"
    EXCEPTION = "exception"
    SERIALIZATION = "serialization"
    STREAM = "stream"
    CONNECTOR_ERROR = "connector_error"


class CredentialBrokerPhase(StrEnum):
    """Credential lifecycle phase represented in content-free audit events."""

    ISSUE = "issue"
    RESOLVE = "resolve"
    REVOKE = "revoke"
    ROTATE = "rotate"
    INSPECT = "inspect"


class CredentialCapabilityState(StrEnum):
    """Atomic state result for a short-lived capability."""

    STORED = "stored"
    CONSUMED = "consumed"
    REPLAYED = "replayed"
    REVOKED = "revoked"
    EXPIRED = "expired"
    MISSING = "missing"
    COLLISION = "collision"


class CredentialBrokerCode(StrEnum):
    """Stable, content-free broker and leak-prevention outcomes."""

    ALLOWED = "allowed"
    REFERENCE_UNKNOWN = "reference_unknown"
    REFERENCE_REVOKED = "reference_revoked"
    BROKER_MISMATCH = "broker_mismatch"
    SCOPE_MISMATCH = "scope_mismatch"
    EXECUTION_INVALID = "execution_invalid"
    EXECUTION_EXPIRED = "execution_expired"
    CAPABILITY_INVALID = "capability_invalid"
    CAPABILITY_EXPIRED = "capability_expired"
    CAPABILITY_REPLAYED = "capability_replayed"
    CAPABILITY_REVOKED = "capability_revoked"
    STATE_UNAVAILABLE = "state_unavailable"
    VAULT_UNAVAILABLE = "vault_unavailable"
    VERSION_CHANGED = "version_changed"
    RAW_CREDENTIAL = "raw_credential"
    CREDENTIAL_OBJECT = "credential_object"
    SUSPICIOUS_FIELD = "suspicious_field"
    INSPECTION_LIMIT = "inspection_limit"
    UNSUPPORTED_VALUE = "unsupported_value"


class CredentialReference(BaseModel):
    """Opaque, non-secret handle safe to expose to an agent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    broker_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    reference_id: str = Field(pattern=_REFERENCE_PATTERN)

    @property
    def reference_digest(self) -> str:
        return credential_digest(self.model_dump(mode="json"))

    def __str__(self) -> str:
        return self.reference_id


class CredentialScope(BaseModel):
    """Exact downstream boundary to which credential use is confined."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tool_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    resource_id: str = Field(min_length=1, max_length=1_024)
    operation: str = Field(pattern=_IDENTIFIER_PATTERN)

    @property
    def scope_digest(self) -> str:
        return credential_digest(self.model_dump(mode="json"))


class CredentialBinding(BaseModel):
    """Trusted policy binding an opaque reference to one exact scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reference: CredentialReference
    scope: CredentialScope
    credential_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    maximum_ttl_seconds: int = Field(default=60, ge=1, le=900)
    active: bool = True


class CredentialBrokerPolicy(BaseModel):
    """Versioned allowlist for brokered credentials."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    broker_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    version: int = Field(ge=1)
    bindings: tuple[CredentialBinding, ...] = Field(min_length=1, max_length=100_000)
    require_one_time_use: Literal[True] = True

    @model_validator(mode="after")
    def validate_bindings(self) -> CredentialBrokerPolicy:
        reference_ids = [item.reference.reference_id for item in self.bindings]
        if len(reference_ids) != len(set(reference_ids)):
            raise ValueError("credential references must be unique")
        if any(item.reference.broker_id != self.broker_id for item in self.bindings):
            raise ValueError("every credential reference must belong to the policy broker")
        return self

    def binding_for(self, reference: CredentialReference) -> CredentialBinding | None:
        """Return the exact configured binding, if any."""
        return next((item for item in self.bindings if item.reference == reference), None)

    @property
    def policy_digest(self) -> str:
        return credential_digest(self.model_dump(mode="json"))


class AuthorizedCredentialExecution(BaseModel):
    """Integrity-bound record from trusted tool authorization infrastructure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    execution_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    authorization_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    scope: CredentialScope
    issued_at: datetime
    expires_at: datetime
    execution_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_execution(self) -> AuthorizedCredentialExecution:
        if self.expires_at <= self.issued_at:
            raise ValueError("execution expires_at must be after issued_at")
        if not self.has_valid_integrity:
            raise ValueError("execution integrity check failed")
        return self

    @classmethod
    def create(
        cls,
        *,
        execution_id: str,
        authorization_id: str,
        request_digest: str,
        scope: CredentialScope,
        issued_at: datetime,
        expires_at: datetime,
    ) -> AuthorizedCredentialExecution:
        payload = {
            "authorization_id": authorization_id,
            "execution_id": execution_id,
            "expires_at": expires_at.isoformat(),
            "issued_at": issued_at.isoformat(),
            "request_digest": request_digest,
            "scope": scope.model_dump(mode="json"),
        }
        return cls(
            execution_id=execution_id,
            authorization_id=authorization_id,
            request_digest=request_digest,
            scope=scope,
            issued_at=issued_at,
            expires_at=expires_at,
            execution_digest=credential_digest(payload),
        )

    @property
    def has_valid_integrity(self) -> bool:
        payload = {
            "authorization_id": self.authorization_id,
            "execution_id": self.execution_id,
            "expires_at": self.expires_at.isoformat(),
            "issued_at": self.issued_at.isoformat(),
            "request_digest": self.request_digest,
            "scope": self.scope.model_dump(mode="json"),
        }
        return self.execution_digest == credential_digest(payload)


class CredentialCapability(BaseModel):
    """Opaque, short-lived authority to resolve one credential exactly once."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    broker_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    reference: CredentialReference
    scope: CredentialScope
    execution_digest: str = Field(pattern=_DIGEST_PATTERN)
    credential_version: str = Field(pattern=_IDENTIFIER_PATTERN)
    policy_digest: str = Field(pattern=_DIGEST_PATTERN)
    issued_at: datetime
    expires_at: datetime
    one_time: bool = True
    capability_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_capability(self) -> CredentialCapability:
        if self.expires_at <= self.issued_at:
            raise ValueError("capability expires_at must be after issued_at")
        if not self.has_valid_integrity:
            raise ValueError("capability integrity check failed")
        return self

    @classmethod
    def create(
        cls,
        *,
        capability_id: str,
        broker_id: str,
        reference: CredentialReference,
        scope: CredentialScope,
        execution_digest: str,
        credential_version: str,
        policy_digest: str,
        issued_at: datetime,
        expires_at: datetime,
        one_time: bool,
    ) -> CredentialCapability:
        payload = {
            "broker_id": broker_id,
            "capability_id": capability_id,
            "credential_version": credential_version,
            "execution_digest": execution_digest,
            "expires_at": expires_at.isoformat(),
            "issued_at": issued_at.isoformat(),
            "one_time": one_time,
            "policy_digest": policy_digest,
            "reference": reference.model_dump(mode="json"),
            "scope": scope.model_dump(mode="json"),
        }
        return cls(
            capability_id=capability_id,
            broker_id=broker_id,
            reference=reference,
            scope=scope,
            execution_digest=execution_digest,
            credential_version=credential_version,
            policy_digest=policy_digest,
            issued_at=issued_at,
            expires_at=expires_at,
            one_time=one_time,
            capability_digest=credential_digest(payload),
        )

    @property
    def has_valid_integrity(self) -> bool:
        payload = {
            "broker_id": self.broker_id,
            "capability_id": self.capability_id,
            "credential_version": self.credential_version,
            "execution_digest": self.execution_digest,
            "expires_at": self.expires_at.isoformat(),
            "issued_at": self.issued_at.isoformat(),
            "one_time": self.one_time,
            "policy_digest": self.policy_digest,
            "reference": self.reference.model_dump(mode="json"),
            "scope": self.scope.model_dump(mode="json"),
        }
        return self.capability_digest == credential_digest(payload)


class CredentialBrokerFinding(BaseModel):
    """Content-free explanation for a broker or boundary decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: CredentialBrokerCode
    severity: Severity
    message: str


class CredentialBrokerDecision(BaseModel):
    """Fail-closed decision that never contains credential material."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    capability: CredentialCapability | None = None
    findings: tuple[CredentialBrokerFinding, ...] = ()

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW


class CredentialBoundaryDecision(BaseModel):
    """Result of inspecting one model-visible boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK]
    surface: CredentialSurface
    findings: tuple[CredentialBrokerFinding, ...] = ()

    @property
    def is_safe(self) -> bool:
        return self.action == GuardAction.ALLOW


class CredentialAuditEvent(BaseModel):
    """Content-free evidence for credential lifecycle and leak decisions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    occurred_at: datetime
    phase: CredentialBrokerPhase
    code: CredentialBrokerCode
    reference_ref: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    execution_ref: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    capability_ref: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    surface: CredentialSurface | None = None

    @field_validator("occurred_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "occurred_at")
