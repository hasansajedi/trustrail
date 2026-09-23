"""Typed contracts for OWASP ASI10 runtime-invariant enforcement."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_KEY_ID_PATTERN = r"^sha256:[0-9a-f]{64}$"
_SIGNATURE_PATTERN = r"^[0-9a-f]{128}$"


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


def _canonicalize(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, BaseModel):
        return _canonicalize(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(key)): _canonicalize(item)
            for key, item in value.items()
        }
    if isinstance(value, (set, frozenset)):
        items = [_canonicalize(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    return value


def canonical_runtime_json(value: Any) -> str:
    """Serialize runtime-control data with a deterministic signing profile."""
    return json.dumps(
        _canonicalize(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def runtime_digest(value: Any) -> str:
    """Return a stable SHA-256 digest for security-relevant runtime data."""
    return hashlib.sha256(canonical_runtime_json(value).encode()).hexdigest()


def runtime_reference(value: str | bytes) -> str:
    """Return a one-way identifier suitable for content-free audit evidence."""
    encoded = value.encode() if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


class RuntimeEventKind(StrEnum):
    """Events observed by a trusted runtime mediation layer."""

    ACTION = "action"
    COMMUNICATION = "communication"
    CAPABILITY_ACQUIRED = "capability_acquired"
    PERSISTENCE_CREATED = "persistence_created"
    SELF_MODIFICATION = "self_modification"
    CORRECTION_REJECTED = "correction_rejected"
    SHUTDOWN_ACKNOWLEDGED = "shutdown_acknowledged"


class AgentRuntimeStatus(StrEnum):
    """Externally enforced runtime state."""

    ACTIVE = "active"
    STOPPING = "stopping"
    SUSPENDED = "suspended"
    QUARANTINED = "quarantined"


class RogueAgentCode(StrEnum):
    """Stable machine-readable ASI10 findings and lifecycle results."""

    EVENT_ALLOWED = "event_allowed"
    MANIFEST_UNSIGNED = "manifest_unsigned"
    MANIFEST_KEY_UNKNOWN = "manifest_key_unknown"
    MANIFEST_SIGNATURE_INVALID = "manifest_signature_invalid"
    MANIFEST_EXPIRED = "manifest_expired"
    MANIFEST_CONTEXT_MISMATCH = "manifest_context_mismatch"
    EVENT_INTEGRITY_INVALID = "event_integrity_invalid"
    EVENT_CONTEXT_MISMATCH = "event_context_mismatch"
    EVENT_OUT_OF_ORDER = "event_out_of_order"
    ACTION_NOT_ALLOWED = "action_not_allowed"
    TOOL_NOT_ALLOWED = "tool_not_allowed"
    PEER_NOT_ALLOWED = "peer_not_allowed"
    CAPABILITY_NOT_ALLOWED = "capability_not_allowed"
    CAPABILITY_CEILING_EXCEEDED = "capability_ceiling_exceeded"
    ACTION_CEILING_EXCEEDED = "action_ceiling_exceeded"
    COMMUNICATION_CEILING_EXCEEDED = "communication_ceiling_exceeded"
    CONCEALED_ACTION = "concealed_action"
    BOUNDARY_PROBING = "boundary_probing"
    UNAUTHORIZED_PERSISTENCE = "unauthorized_persistence"
    SELF_MODIFICATION = "self_modification"
    CORRECTION_RESISTANCE = "correction_resistance"
    STOP_REQUESTED = "stop_requested"
    STOP_RESISTANCE = "stop_resistance"
    SHUTDOWN_ACKNOWLEDGED = "shutdown_acknowledged"
    AGENT_NOT_ACTIVE = "agent_not_active"
    CONTAINMENT_HOOK_FAILED = "containment_hook_failed"
    RECOVERY_DENIED = "recovery_denied"
    RECOVERY_REPLAYED = "recovery_replayed"
    RECOVERY_ALLOWED = "recovery_allowed"


class RuntimeCapabilityCeiling(BaseModel):
    """Finite per-session limits that an agent cannot expand at runtime."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_actions: int = Field(default=1_000, ge=1, le=10_000_000)
    max_communications: int = Field(default=1_000, ge=0, le=10_000_000)
    max_capability_acquisitions: int = Field(default=0, ge=0, le=100_000)


class RuntimeInvariantManifest(BaseModel):
    """Ed25519-signed, immutable behavioral authority for one agent session."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    manifest_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    revision: int = Field(ge=1, le=2_147_483_647)
    agent_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    allowed_actions: frozenset[str] = Field(min_length=1, max_length=10_000)
    allowed_tools: frozenset[str] = Field(default_factory=frozenset, max_length=10_000)
    allowed_peers: frozenset[str] = Field(default_factory=frozenset, max_length=10_000)
    allowed_capabilities: frozenset[str] = Field(default_factory=frozenset, max_length=10_000)
    capability_ceiling: RuntimeCapabilityCeiling = Field(default_factory=RuntimeCapabilityCeiling)
    allow_persistence: bool = False
    allow_self_modification: bool = False
    max_boundary_probes: int = Field(default=2, ge=0, le=100_000)
    shutdown_grace_events: int = Field(default=0, ge=0, le=100)
    issued_at: datetime
    expires_at: datetime
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @field_validator(
        "allowed_actions",
        "allowed_tools",
        "allowed_peers",
        "allowed_capabilities",
    )
    @classmethod
    def validate_identifiers(cls, values: frozenset[str], info: Any) -> frozenset[str]:
        if any(re.fullmatch(_IDENTIFIER_PATTERN, value) is None for value in values):
            raise ValueError(f"{info.field_name} contains an invalid identifier")
        return values

    @model_validator(mode="after")
    def validate_lifetime(self) -> RuntimeInvariantManifest:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self

    @property
    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})

    @property
    def signing_bytes(self) -> bytes:
        return canonical_runtime_json(self.signing_payload).encode()

    @property
    def manifest_digest(self) -> str:
        return runtime_digest({"payload": self.signing_payload, "signature": self.signature})


class RuntimeInvariantTrustedKey(BaseModel):
    """Out-of-band authority key used to verify invariant manifests."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authority_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    public_key: bytes = Field(min_length=32, max_length=32, exclude=True, repr=False)
    active_from: datetime | None = None
    expires_at: datetime | None = None
    revoked: bool = False

    @field_validator("active_from", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime | None, info: Any) -> datetime | None:
        if value is not None:
            return _require_aware(value, info.field_name)
        return value

    @model_validator(mode="after")
    def validate_lifetime(self) -> RuntimeInvariantTrustedKey:
        if (
            self.active_from is not None
            and self.expires_at is not None
            and self.expires_at <= self.active_from
        ):
            raise ValueError("trusted key expires_at must be after active_from")
        return self

    @property
    def key_id(self) -> str:
        return runtime_reference(self.public_key)


class RuntimeEvent(BaseModel):
    """Integrity-bound observation emitted by a trusted runtime interceptor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    sequence: int = Field(ge=0, le=9_223_372_036_854_775_807)
    agent_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    kind: RuntimeEventKind
    occurred_at: datetime
    action: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    tool: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    peer_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    capability: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    disclosed: bool = True
    boundary_denied: bool = False
    event_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "occurred_at")

    @model_validator(mode="after")
    def validate_kind_fields(self) -> RuntimeEvent:
        required = {
            RuntimeEventKind.ACTION: ("action",),
            RuntimeEventKind.COMMUNICATION: ("peer_id",),
            RuntimeEventKind.CAPABILITY_ACQUIRED: ("capability",),
        }
        for field_name in required.get(self.kind, ()):
            if getattr(self, field_name) is None:
                raise ValueError(f"{self.kind.value} events require {field_name}")
        if not self.has_valid_integrity:
            raise ValueError("runtime event integrity check failed")
        return self

    @classmethod
    def create(cls, **values: Any) -> RuntimeEvent:
        """Create an event whose digest covers every security-relevant field."""
        candidate = cls.model_construct(**values, event_digest="0" * 64)
        payload = candidate.model_dump(mode="json", exclude={"event_digest"})
        return cls(**payload, event_digest=runtime_digest(payload))

    @property
    def has_valid_integrity(self) -> bool:
        payload = self.model_dump(mode="json", exclude={"event_digest"})
        return self.event_digest == runtime_digest(payload)


class RogueAgentFinding(BaseModel):
    """Content-free explanation of a runtime decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: RogueAgentCode
    severity: Severity
    message: str


class RogueAgentAuditEvent(BaseModel):
    """Metadata-only evidence emitted for every decision and lifecycle change."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    audit_sequence: int = Field(ge=1)
    code: RogueAgentCode
    action: GuardAction
    status: AgentRuntimeStatus
    agent_ref: str = Field(pattern=_KEY_ID_PATTERN)
    tenant_ref: str = Field(pattern=_KEY_ID_PATTERN)
    session_ref: str = Field(pattern=_KEY_ID_PATTERN)
    event_ref: str | None = Field(default=None, pattern=_KEY_ID_PATTERN)
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "occurred_at")


class RogueAgentResult(BaseModel):
    """Decision returned by monitoring, containment, stop, and recovery APIs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: GuardAction
    status: AgentRuntimeStatus
    findings: tuple[RogueAgentFinding, ...] = ()
    events: tuple[RogueAgentAuditEvent, ...] = ()

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW


class RuntimeRecoveryGrant(BaseModel):
    """Single-use authorization delivered through an isolated recovery path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    agent_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    quarantined_manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    replacement_manifest_digest: str = Field(pattern=_DIGEST_PATTERN)
    issued_at: datetime
    expires_at: datetime
    isolated_channel: Literal[True] = True
    grant_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_grant(self) -> RuntimeRecoveryGrant:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if not self.has_valid_integrity:
            raise ValueError("recovery grant integrity check failed")
        return self

    @classmethod
    def create(cls, **values: Any) -> RuntimeRecoveryGrant:
        candidate = cls.model_construct(**values, grant_digest="0" * 64)
        payload = candidate.model_dump(mode="json", exclude={"grant_digest"})
        return cls(**payload, grant_digest=runtime_digest(payload))

    @property
    def has_valid_integrity(self) -> bool:
        payload = self.model_dump(mode="json", exclude={"grant_digest"})
        return self.grant_digest == runtime_digest(payload)
