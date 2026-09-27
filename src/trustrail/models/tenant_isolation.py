"""Typed contracts for multi-tenant AI state and cache isolation."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.data_labels import canonical_data_label_json
from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_REFERENCE_PATTERN = r"^(sha256|hmac-sha256):[0-9a-f]{64}$"
_KEY_ID_PATTERN = r"^sha256:[0-9a-f]{64}$"
_SIGNATURE_PATTERN = r"^[0-9a-f]{128}$"
_TAG_PATTERN = r"^[0-9a-f]{64}$"


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def tenant_isolation_digest(value: object) -> str:
    """Return a deterministic SHA-256 digest for isolation metadata."""
    return hashlib.sha256(canonical_data_label_json(value).encode()).hexdigest()


def tenant_isolation_reference(value: str | bytes) -> str:
    """Return a content-safe reference for audit and decision evidence."""
    raw = value.encode() if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class TenantStateKind(StrEnum):
    """Tenant-owned AI state that must never use an unscoped key."""

    PROMPT_CACHE = "prompt_cache"
    RESPONSE_CACHE = "response_cache"
    SEMANTIC_CACHE = "semantic_cache"
    KV_CACHE = "kv_cache"
    EMBEDDING = "embedding"
    MEMORY = "memory"
    ADAPTER = "adapter"
    SESSION = "session"
    BUDGET = "budget"
    AUDIT = "audit"


class TenantStateOperation(StrEnum):
    """Security-relevant operations over tenant-bound state."""

    READ = "read"
    WRITE = "write"
    CACHE_HIT = "cache_hit"
    ADAPTER_USE = "adapter_use"
    RESTORE = "restore"


class IsolationLevel(StrEnum):
    """Claimed infrastructure isolation level, ordered by strength."""

    LOGICAL = "logical"
    PROCESS = "process"
    HARDWARE = "hardware"


class TenantIsolationCode(StrEnum):
    """Stable machine-readable multi-tenant isolation findings."""

    ALLOWED = "allowed"
    CONTEXT_MISSING = "context_missing"
    CONTEXT_UNSIGNED = "context_unsigned"
    CONTEXT_KEY_UNKNOWN = "context_key_unknown"
    CONTEXT_ISSUER_MISMATCH = "context_issuer_mismatch"
    CONTEXT_SIGNATURE_INVALID = "context_signature_invalid"
    CONTEXT_EXPIRED = "context_expired"
    STATE_KIND_DENIED = "state_kind_denied"
    OPERATION_DENIED = "operation_denied"
    STATE_KEY_INVALID = "state_key_invalid"
    STATE_KEY_COLLISION = "state_key_collision"
    STATE_BINDING_MISSING = "state_binding_missing"
    STATE_BINDING_INVALID = "state_binding_invalid"
    STATE_TENANT_MISMATCH = "state_tenant_mismatch"
    STATE_KIND_MISMATCH = "state_kind_mismatch"
    CACHE_HIT_CROSS_TENANT = "cache_hit_cross_tenant"
    BATCH_CROSS_TENANT = "batch_cross_tenant"
    ADAPTER_CROSS_TENANT = "adapter_cross_tenant"
    RESTORE_CROSS_TENANT = "restore_cross_tenant"
    RETENTION_DENIED = "retention_denied"
    ATTESTATION_REQUIRED = "attestation_required"
    ATTESTATION_UNSIGNED = "attestation_unsigned"
    ATTESTATION_KEY_UNKNOWN = "attestation_key_unknown"
    ATTESTATION_ISSUER_MISMATCH = "attestation_issuer_mismatch"
    ATTESTATION_SIGNATURE_INVALID = "attestation_signature_invalid"
    ATTESTATION_EXPIRED = "attestation_expired"
    ATTESTATION_SCOPE_MISMATCH = "attestation_scope_mismatch"
    ATTESTATION_LEVEL_INSUFFICIENT = "attestation_level_insufficient"


class TenantSecurityContext(BaseModel):
    """Short-lived, signed tenant authority propagated through a request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    context_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issuer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    principal_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    allowed_state_kinds: frozenset[TenantStateKind] = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(pattern=_IDENTIFIER_PATTERN)
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: object) -> datetime:
        field_name = getattr(info, "field_name", "timestamp")
        return _require_aware(value, field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> TenantSecurityContext:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self

    @property
    def signing_bytes(self) -> bytes:
        return canonical_data_label_json(
            self.model_dump(mode="python", exclude={"signature"})
        ).encode()

    @property
    def context_digest(self) -> str:
        return tenant_isolation_digest(self.model_dump(mode="python"))


class TenantContextTrustedKey(BaseModel):
    """Pinned tenant-context issuer key and tenant authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    public_key: bytes = Field(min_length=32, max_length=32)
    allowed_tenant_ids: frozenset[str] = Field(min_length=1)
    active_from: datetime | None = None
    expires_at: datetime | None = None
    revoked: bool = False

    @field_validator("allowed_tenant_ids")
    @classmethod
    def validate_tenants(cls, value: frozenset[str]) -> frozenset[str]:
        for tenant_id in value:
            if not tenant_id or len(tenant_id) > 256:
                raise ValueError("tenant identifiers must be between 1 and 256 characters")
        return value

    @field_validator("active_from", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime | None, info: object) -> datetime | None:
        if value is None:
            return None
        field_name = getattr(info, "field_name", "timestamp")
        return _require_aware(value, field_name)

    @property
    def key_id(self) -> str:
        return tenant_isolation_reference(self.public_key)


class TenantStateRule(BaseModel):
    """Isolation requirements for one tenant-owned AI state category."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state_kind: TenantStateKind
    allowed_operations: frozenset[TenantStateOperation] = Field(min_length=1)
    maximum_ttl_seconds: int = Field(default=86_400, ge=1, le=31_536_000)
    required_isolation_level: IsolationLevel = IsolationLevel.LOGICAL
    require_dedicated_tenant: bool = False

    @model_validator(mode="after")
    def validate_dedicated_level(self) -> TenantStateRule:
        if (
            self.require_dedicated_tenant
            and self.required_isolation_level == IsolationLevel.LOGICAL
        ):
            raise ValueError("dedicated tenant isolation requires process or hardware isolation")
        return self


class TenantIsolationPolicy(BaseModel):
    """Complete policy for every supported tenant-owned state category."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    version: int = Field(ge=1)
    rules: tuple[TenantStateRule, ...] = Field(min_length=len(TenantStateKind))
    forbid_cross_tenant_batches: Literal[True] = True

    @model_validator(mode="after")
    def validate_complete_policy(self) -> TenantIsolationPolicy:
        kinds = [rule.state_kind for rule in self.rules]
        if len(kinds) != len(set(kinds)):
            raise ValueError("tenant state rules must not contain duplicate state kinds")
        if set(kinds) != set(TenantStateKind):
            raise ValueError("tenant isolation policy must cover every state kind")
        return self

    def rule_for(self, state_kind: TenantStateKind) -> TenantStateRule:
        """Return the complete rule for ``state_kind``."""
        return next(rule for rule in self.rules if rule.state_kind == state_kind)

    @classmethod
    def strict(
        cls,
        *,
        policy_id: str,
        version: int = 1,
        process_isolated: frozenset[TenantStateKind] = frozenset(),
        hardware_isolated: frozenset[TenantStateKind] = frozenset(),
        dedicated_tenant: frozenset[TenantStateKind] = frozenset(),
        maximum_ttl_seconds: int = 86_400,
    ) -> TenantIsolationPolicy:
        """Build a default-deny policy with explicit rules for every state kind."""
        if process_isolated & hardware_isolated:
            raise ValueError("a state kind cannot require two isolation levels")
        if not dedicated_tenant <= process_isolated | hardware_isolated:
            raise ValueError("dedicated state must require process or hardware isolation")
        cache_kinds = {
            TenantStateKind.PROMPT_CACHE,
            TenantStateKind.RESPONSE_CACHE,
            TenantStateKind.SEMANTIC_CACHE,
            TenantStateKind.KV_CACHE,
        }
        rules = []
        for state_kind in TenantStateKind:
            operations = {
                TenantStateOperation.READ,
                TenantStateOperation.WRITE,
                TenantStateOperation.RESTORE,
            }
            if state_kind in cache_kinds:
                operations.add(TenantStateOperation.CACHE_HIT)
            if state_kind == TenantStateKind.ADAPTER:
                operations.add(TenantStateOperation.ADAPTER_USE)
            level = IsolationLevel.LOGICAL
            if state_kind in process_isolated:
                level = IsolationLevel.PROCESS
            elif state_kind in hardware_isolated:
                level = IsolationLevel.HARDWARE
            rules.append(
                TenantStateRule(
                    state_kind=state_kind,
                    allowed_operations=frozenset(operations),
                    maximum_ttl_seconds=maximum_ttl_seconds,
                    required_isolation_level=level,
                    require_dedicated_tenant=state_kind in dedicated_tenant,
                )
            )
        return cls(policy_id=policy_id, version=version, rules=tuple(rules))


class TenantStateKey(BaseModel):
    """Opaque domain-separated storage key and its expected ownership."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    storage_key: str = Field(min_length=64, max_length=512)
    namespace_ref: str = Field(pattern=_REFERENCE_PATTERN)
    tenant_ref: str = Field(pattern=_REFERENCE_PATTERN)
    state_kind: TenantStateKind
    partition_ref: str = Field(pattern=_REFERENCE_PATTERN)
    artifact_ref: str = Field(pattern=_REFERENCE_PATTERN)
    context_digest: str = Field(pattern=_DIGEST_PATTERN)

    @property
    def owner_digest(self) -> str:
        return tenant_isolation_digest(
            {
                "namespace_ref": self.namespace_ref,
                "tenant_ref": self.tenant_ref,
                "state_kind": self.state_kind,
                "partition_ref": self.partition_ref,
                "artifact_ref": self.artifact_ref,
            }
        )


class TenantStateBinding(BaseModel):
    """Integrity-bound tenant ownership stored beside an AI state value."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    storage_key: str = Field(min_length=64, max_length=512)
    owner_digest: str = Field(pattern=_DIGEST_PATTERN)
    tenant_ref: str = Field(pattern=_REFERENCE_PATTERN)
    state_kind: TenantStateKind
    artifact_ref: str = Field(pattern=_REFERENCE_PATTERN)
    context_digest: str = Field(pattern=_DIGEST_PATTERN)
    created_at: datetime
    expires_at: datetime
    integrity_tag: str = Field(pattern=_TAG_PATTERN)

    @field_validator("created_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: object) -> datetime:
        field_name = getattr(info, "field_name", "timestamp")
        return _require_aware(value, field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> TenantStateBinding:
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        return self

    @property
    def signing_payload(self) -> dict[str, object]:
        return self.model_dump(mode="python", exclude={"integrity_tag"})


class DeploymentIsolationAttestation(BaseModel):
    """Signed deployment claim supplied by an external attestation authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    attestation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issuer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    deployment_ref: str = Field(pattern=_REFERENCE_PATTERN)
    isolation_level: IsolationLevel
    covered_state_kinds: frozenset[TenantStateKind] = Field(min_length=1)
    dedicated_tenant_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    measurement_digest: str = Field(pattern=_DIGEST_PATTERN)
    issued_at: datetime
    expires_at: datetime
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime, info: object) -> datetime:
        field_name = getattr(info, "field_name", "timestamp")
        return _require_aware(value, field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> DeploymentIsolationAttestation:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self

    @property
    def signing_bytes(self) -> bytes:
        return canonical_data_label_json(
            self.model_dump(mode="python", exclude={"signature"})
        ).encode()

    @property
    def attestation_digest(self) -> str:
        return tenant_isolation_digest(self.model_dump(mode="python"))


class DeploymentAttestationTrustedKey(BaseModel):
    """Pinned external attestor key and authorized deployments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    public_key: bytes = Field(min_length=32, max_length=32)
    allowed_deployment_refs: frozenset[str] = Field(min_length=1)
    active_from: datetime | None = None
    expires_at: datetime | None = None
    revoked: bool = False

    @field_validator("allowed_deployment_refs")
    @classmethod
    def validate_deployments(cls, value: frozenset[str]) -> frozenset[str]:
        for deployment_ref in value:
            if not deployment_ref.startswith("sha256:") or len(deployment_ref) != 71:
                raise ValueError("allowed deployment references must be SHA-256 references")
        return value

    @field_validator("active_from", "expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime | None, info: object) -> datetime | None:
        if value is None:
            return None
        field_name = getattr(info, "field_name", "timestamp")
        return _require_aware(value, field_name)

    @property
    def key_id(self) -> str:
        return tenant_isolation_reference(self.public_key)


class TenantStateAccessRequest(BaseModel):
    """One exact tenant-state operation to mediate before touching storage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    context: TenantSecurityContext | None
    state_kind: TenantStateKind
    operation: TenantStateOperation
    artifact_id: str = Field(min_length=1, max_length=4_096)
    partition_id: str = Field(default="default", min_length=1, max_length=1_024)
    state_key: TenantStateKey | None
    observed_binding: TenantStateBinding | None = None
    requested_expires_at: datetime | None = None
    deployment_id: str | None = Field(default=None, min_length=1, max_length=1_024)
    attestation: DeploymentIsolationAttestation | None = None

    @field_validator("requested_expires_at")
    @classmethod
    def validate_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _require_aware(value, "requested_expires_at")


class TenantBatchRequest(BaseModel):
    """Inference batch whose tenant composition must be checked before enqueue."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    contexts: tuple[TenantSecurityContext, ...] = Field(min_length=1, max_length=10_000)
    state_kind: TenantStateKind = TenantStateKind.KV_CACHE
    deployment_id: str | None = Field(default=None, min_length=1, max_length=1_024)
    attestation: DeploymentIsolationAttestation | None = None


class TenantIsolationFinding(BaseModel):
    """Content-free explanation for an isolation decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: TenantIsolationCode
    severity: Severity
    message: str


class DeploymentAttestationEvidence(BaseModel):
    """What the library validated, without claiming infrastructure proof."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    attestation_digest: str = Field(pattern=_DIGEST_PATTERN)
    deployment_ref: str = Field(pattern=_REFERENCE_PATTERN)
    claimed_isolation_level: IsolationLevel
    validation_scope: Literal["signature_and_claims_only"] = "signature_and_claims_only"
    infrastructure_verified: Literal[False] = False


class AuthorizedTenantStateAccess(BaseModel):
    """Exact tenant-bound state permit returned after fail-closed validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    permit_id: str = Field(pattern=_DIGEST_PATTERN)
    context_digest: str = Field(pattern=_DIGEST_PATTERN)
    tenant_ref: str = Field(pattern=_REFERENCE_PATTERN)
    state_kind: TenantStateKind
    operation: TenantStateOperation
    storage_key: str = Field(min_length=64, max_length=512)
    binding: TenantStateBinding | None = None


class AuthorizedTenantBatch(BaseModel):
    """Single-tenant inference-batch permit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    permit_id: str = Field(pattern=_DIGEST_PATTERN)
    tenant_ref: str = Field(pattern=_REFERENCE_PATTERN)
    state_kind: TenantStateKind
    context_digests: tuple[str, ...] = Field(min_length=1)


class TenantIsolationAuditEvent(BaseModel):
    """Content-free audit event for a tenant-isolation decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    occurred_at: datetime
    action: GuardAction
    code: TenantIsolationCode
    request_ref: str = Field(pattern=_REFERENCE_PATTERN)
    tenant_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    state_kind: TenantStateKind
    operation: TenantStateOperation | Literal["batch"]
    state_key_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    attestation_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)


class TenantIsolationDecision(BaseModel):
    """Fail-closed result for state access or inference batching."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: GuardAction
    findings: tuple[TenantIsolationFinding, ...] = ()
    access_permit: AuthorizedTenantStateAccess | None = None
    batch_permit: AuthorizedTenantBatch | None = None
    attestation_evidence: DeploymentAttestationEvidence | None = None
    audit_event: TenantIsolationAuditEvent

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW
