"""Typed provenance, taint, and remediation contracts for persistent memory."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity, TrustLevel

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
MemoryIdentifier = Annotated[str, Field(pattern=_IDENTIFIER_PATTERN)]


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def _canonicalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _canonicalize(value.model_dump(mode="json"))
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _canonicalize(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        items = [_canonicalize(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    return value


def _digest(payload: Any) -> str:
    canonical = json.dumps(
        _canonicalize(payload),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _content_digest(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class MemoryContentKind(StrEnum):
    """Semantic form persisted by a memory backend."""

    FACT = "fact"
    SUMMARY = "summary"
    PREFERENCE = "preference"
    PROFILE = "profile"
    INSTRUCTION = "instruction"
    EMBEDDING = "embedding"
    CONTEXT = "context"


class MemoryScope(StrEnum):
    """Audience boundary for a persistent memory."""

    USER = "user"
    TENANT = "tenant"
    GLOBAL = "global"


class MemorySourceKind(StrEnum):
    """Origin classes carried through every memory transformation."""

    USER = "user"
    MODEL = "model"
    TOOL = "tool"
    IMPORT = "import"
    ADMIN = "admin"
    REBUILT = "rebuilt"


class MemoryTransformationKind(StrEnum):
    """How a record was produced from its declared dependencies."""

    DIRECT = "direct"
    SUMMARY = "summary"
    MERGE = "merge"
    EMBEDDING = "embedding"
    MIGRATION = "migration"
    REBUILD = "rebuild"


class MemoryTaintStatus(StrEnum):
    """Lifecycle state used to gate retrieval."""

    CLEAN = "clean"
    REVIEWED = "reviewed"
    SUSPECT = "suspect"
    TAINTED = "tainted"
    QUARANTINED = "quarantined"
    INVALIDATED = "invalidated"


class MemoryRiskSignal(StrEnum):
    """Content-free taint evidence preserved with a record."""

    INSTRUCTION_BEARING = "instruction_bearing"
    ROLE_CHANGING = "role_changing"
    SECURITY_POLICY = "security_policy"
    DELAYED_TRIGGER = "delayed_trigger"
    SPLIT_ENTRY = "split_entry"
    CROSS_USER = "cross_user"
    SHARED_SCOPE = "shared_scope"
    SUMMARY_LAUNDERING = "summary_laundering"
    TAINT_INHERITANCE = "taint_inheritance"
    PROVENANCE_DROPPED = "provenance_dropped"
    INTEGRITY_MISMATCH = "integrity_mismatch"
    UNTRUSTED_SOURCE = "untrusted_source"


class MemoryTaintCode(StrEnum):
    """Stable machine-readable memory security findings."""

    REQUEST_INTEGRITY_INVALID = "request_integrity_invalid"
    RECORD_INTEGRITY_INVALID = "record_integrity_invalid"
    CONTENT_INTEGRITY_INVALID = "content_integrity_invalid"
    MEMORY_ALREADY_EXISTS = "memory_already_exists"
    MEMORY_UNKNOWN = "memory_unknown"
    DEPENDENCY_UNKNOWN = "dependency_unknown"
    DEPENDENCY_REBOUND = "dependency_rebound"
    PROVENANCE_DROPPED = "provenance_dropped"
    TENANT_MISMATCH = "tenant_mismatch"
    PURPOSE_MISMATCH = "purpose_mismatch"
    CROSS_USER_WRITE = "cross_user_write"
    SHARED_WRITE_UNAUTHORIZED = "shared_write_unauthorized"
    PRIVILEGED_WRITE_REQUIRES_APPROVAL = "privileged_write_requires_approval"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_REPLAYED = "approval_replayed"
    INSTRUCTION_MEMORY = "instruction_memory"
    ROLE_CHANGE_MEMORY = "role_change_memory"
    SECURITY_POLICY_MEMORY = "security_policy_memory"
    DELAYED_TRIGGER_MEMORY = "delayed_trigger_memory"
    SPLIT_ENTRY_POISONING = "split_entry_poisoning"
    SUMMARY_LAUNDERING = "summary_laundering"
    TAINTED_DEPENDENCY = "tainted_dependency"
    AUTHORIZATION_INVALID = "authorization_invalid"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    AUTHORIZATION_REPLAYED = "authorization_replayed"
    RETRIEVAL_DENIED = "retrieval_denied"
    MEMORY_QUARANTINED = "memory_quarantined"
    MEMORY_INVALIDATED = "memory_invalidated"
    REVALIDATION_INVALID = "revalidation_invalid"
    REVALIDATION_REJECTED = "revalidation_rejected"
    REBUILD_REQUIRED = "rebuild_required"
    HOOK_FAILED = "hook_failed"


class MemoryEventKind(StrEnum):
    """Metadata-only audit event kinds for memory lifecycle changes."""

    WRITE_ALLOWED = "write_allowed"
    WRITE_DENIED = "write_denied"
    WRITE_COMMITTED = "write_committed"
    WRITE_ABANDONED = "write_abandoned"
    RETRIEVAL_ALLOWED = "retrieval_allowed"
    RETRIEVAL_DENIED = "retrieval_denied"
    QUARANTINED = "quarantined"
    INVALIDATED = "invalidated"
    REVALIDATED = "revalidated"
    REVALIDATION_DENIED = "revalidation_denied"
    REBUILD_REQUESTED = "rebuild_requested"
    HOOK_FAILED = "hook_failed"


class MemoryProvenance(BaseModel):
    """Immutable source and writer identity carried into derived memories."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    source_kind: MemorySourceKind
    trust_level: TrustLevel
    writer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "observed_at")


class MemoryDependency(BaseModel):
    """Integrity-bound edge to an input memory record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    memory_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    record_digest: str = Field(pattern=_DIGEST_PATTERN)


class MemoryRecord(BaseModel):
    """Content-free metadata envelope stored beside persistent memory bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    memory_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    version: int = Field(default=1, ge=1)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    owner_user_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    writer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    content_kind: MemoryContentKind
    scope: MemoryScope = MemoryScope.USER
    transformation: MemoryTransformationKind = MemoryTransformationKind.DIRECT
    provenance: tuple[MemoryProvenance, ...] = Field(min_length=1, max_length=10_000)
    dependencies: tuple[MemoryDependency, ...] = Field(default_factory=tuple, max_length=10_000)
    taint_status: MemoryTaintStatus = MemoryTaintStatus.CLEAN
    taint_signals: frozenset[MemoryRiskSignal] = Field(default_factory=frozenset)
    approval_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    content_digest: str = Field(pattern=_DIGEST_PATTERN)
    created_at: datetime
    expires_at: datetime | None = None
    record_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("created_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime | None, info: Any) -> datetime | None:
        return None if value is None else _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_record(self) -> MemoryRecord:
        if self.scope == MemoryScope.USER and self.owner_user_id is None:
            raise ValueError("user-scoped memory requires owner_user_id")
        if self.scope != MemoryScope.USER and self.owner_user_id is not None:
            raise ValueError("shared memory must not claim a single user owner")
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if len({item.source_id for item in self.provenance}) != len(self.provenance):
            raise ValueError("provenance source IDs must be unique")
        if len({item.memory_id for item in self.dependencies}) != len(self.dependencies):
            raise ValueError("memory dependencies must be unique")
        if any(item.memory_id == self.memory_id for item in self.dependencies):
            raise ValueError("memory cannot depend on itself")
        if self.transformation == MemoryTransformationKind.DIRECT and self.dependencies:
            raise ValueError("direct memory must not declare dependencies")
        if self.transformation != MemoryTransformationKind.DIRECT and not self.dependencies:
            raise ValueError("derived memory requires dependencies")
        if any(item.tenant_id != self.tenant_id for item in self.provenance):
            raise ValueError("memory provenance cannot cross tenants")
        if any(item.purpose_id != self.purpose_id for item in self.provenance):
            raise ValueError("memory provenance cannot change purpose")
        if not self.has_valid_integrity:
            raise ValueError("memory record integrity check failed")
        return self

    @classmethod
    def create(cls, *, content: str, **values: Any) -> MemoryRecord:
        """Build a record whose digests bind content and every metadata field."""
        candidate = cls.model_construct(
            **values,
            content_digest=_content_digest(content),
            record_digest="0" * 64,
        )
        payload = candidate.model_dump(exclude={"record_digest"})
        return cls(**payload, record_digest=_digest(payload))

    @property
    def has_valid_integrity(self) -> bool:
        return self.record_digest == _digest(self.model_dump(exclude={"record_digest"}))

    def matches_content(self, content: str) -> bool:
        """Return whether bytes match the record without retaining them."""
        return self.content_digest == _content_digest(content)

    def transition(
        self,
        *,
        status: MemoryTaintStatus,
        signals: frozenset[MemoryRiskSignal] | None = None,
        approval_id: str | None = None,
        preserve_approval: bool = True,
        version: int | None = None,
        transformation: MemoryTransformationKind | None = None,
    ) -> MemoryRecord:
        """Create an integrity-valid metadata revision without content access."""
        values = self.model_dump(exclude={"record_digest"})
        values.update(
            taint_status=status,
            taint_signals=signals if signals is not None else self.taint_signals,
            approval_id=(
                approval_id
                if approval_id is not None
                else self.approval_id
                if preserve_approval
                else None
            ),
            version=version if version is not None else self.version,
            transformation=transformation or self.transformation,
        )
        return type(self)(**values, record_digest=_digest(values))


class MemoryWriteRequest(BaseModel):
    """One exact metadata and content-digest proposal before durable storage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    actor_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    actor_user_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    record: MemoryRecord
    request_digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def validate_request(self) -> MemoryWriteRequest:
        if not self.has_valid_integrity:
            raise ValueError("memory write request integrity check failed")
        return self

    @classmethod
    def create(cls, **values: Any) -> MemoryWriteRequest:
        candidate = cls.model_construct(**values, request_digest="0" * 64)
        payload = candidate.model_dump(exclude={"request_digest"})
        return cls(**payload, request_digest=_digest(payload))

    @property
    def has_valid_integrity(self) -> bool:
        return self.request_digest == _digest(self.model_dump(exclude={"request_digest"}))


class MemoryWriteApproval(BaseModel):
    """Short-lived approval for exact privileged memory signals."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    approved_signals: frozenset[MemoryRiskSignal] = Field(min_length=1)
    approver_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_window(self) -> MemoryWriteApproval:
        if self.expires_at <= self.issued_at:
            raise ValueError("approval expires_at must be after issued_at")
        return self


class AuthorizedMemoryWrite(BaseModel):
    """Short-lived, single-use lease for one effective memory record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    memory_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    record_digest: str = Field(pattern=_DIGEST_PATTERN)
    content_digest: str = Field(pattern=_DIGEST_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issued_at: datetime
    expires_at: datetime
    authorization_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_authorization(self) -> AuthorizedMemoryWrite:
        if self.expires_at <= self.issued_at:
            raise ValueError("authorization expires_at must be after issued_at")
        if not self.has_valid_integrity:
            raise ValueError("memory authorization integrity check failed")
        return self

    @classmethod
    def create(cls, **values: Any) -> AuthorizedMemoryWrite:
        candidate = cls.model_construct(**values, authorization_digest="0" * 64)
        payload = candidate.model_dump(exclude={"authorization_digest"})
        return cls(**payload, authorization_digest=_digest(payload))

    @property
    def has_valid_integrity(self) -> bool:
        return self.authorization_digest == _digest(
            self.model_dump(exclude={"authorization_digest"})
        )


class MemoryReadRequest(BaseModel):
    """Atomic retrieval request bound to a reader, tenant, user, and purpose."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    reader_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    reader_user_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    memory_ids: tuple[MemoryIdentifier, ...] = Field(min_length=1, max_length=10_000)

    @field_validator("memory_ids")
    @classmethod
    def validate_memory_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("retrieval memory IDs must be unique")
        return values


class MemoryRevalidationGrant(BaseModel):
    """Authenticated decision to revalidate one exact quarantined revision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    memory_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    record_digest: str = Field(pattern=_DIGEST_PATTERN)
    content_digest: str = Field(pattern=_DIGEST_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    reviewer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_window(self) -> MemoryRevalidationGrant:
        if self.expires_at <= self.issued_at:
            raise ValueError("revalidation grant expires_at must be after issued_at")
        return self


class MemoryFinding(BaseModel):
    """Content-free explanation of a memory decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: MemoryTaintCode
    severity: Severity
    message: str = Field(min_length=1, max_length=500)
    signals: frozenset[MemoryRiskSignal] = Field(default_factory=frozenset)


class MemoryAuditEvent(BaseModel):
    """Deterministic metadata-only memory lifecycle evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=_DIGEST_PATTERN)
    sequence: int = Field(ge=1)
    kind: MemoryEventKind
    memory_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    action: GuardAction
    finding_codes: tuple[MemoryTaintCode, ...] = ()
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "occurred_at")

    @classmethod
    def create(cls, **values: Any) -> MemoryAuditEvent:
        return cls(**values, event_id=_digest(values))


class MemoryRebuildPlan(BaseModel):
    """Content-free rebuild scope ordered from root to descendants."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    root_memory_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    affected_memory_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    authoritative_source_ids: tuple[str, ...] = Field(max_length=10_000)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    reason_code: str = Field(pattern=_IDENTIFIER_PATTERN)


class MemoryDecision(BaseModel):
    """Write or retrieval decision without persistent-memory content."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: GuardAction
    findings: tuple[MemoryFinding, ...] = ()
    authorization: AuthorizedMemoryWrite | None = None
    record: MemoryRecord | None = None
    records: tuple[MemoryRecord, ...] = ()
    rebuild_plan: MemoryRebuildPlan | None = None
    events: tuple[MemoryAuditEvent, ...] = ()

    @property
    def is_authorized(self) -> bool:
        return self.action == GuardAction.ALLOW


class MemoryTaintPolicy(BaseModel):
    """Fail-closed persistent-memory trust and lifecycle policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trusted_writer_ids: frozenset[MemoryIdentifier] = Field(
        default_factory=frozenset, max_length=10_000
    )
    allowed_purpose_ids: frozenset[MemoryIdentifier] = Field(min_length=1, max_length=10_000)
    privileged_signals: frozenset[MemoryRiskSignal] = frozenset(
        {
            MemoryRiskSignal.INSTRUCTION_BEARING,
            MemoryRiskSignal.ROLE_CHANGING,
            MemoryRiskSignal.SECURITY_POLICY,
            MemoryRiskSignal.DELAYED_TRIGGER,
            MemoryRiskSignal.SHARED_SCOPE,
            MemoryRiskSignal.UNTRUSTED_SOURCE,
        }
    )
    non_overridable_signals: frozenset[MemoryRiskSignal] = frozenset(
        {
            MemoryRiskSignal.SPLIT_ENTRY,
            MemoryRiskSignal.CROSS_USER,
            MemoryRiskSignal.SUMMARY_LAUNDERING,
            MemoryRiskSignal.TAINT_INHERITANCE,
            MemoryRiskSignal.PROVENANCE_DROPPED,
            MemoryRiskSignal.INTEGRITY_MISMATCH,
        }
    )
    authorization_ttl_seconds: int = Field(default=60, ge=1, le=3_600)
    max_recent_entries: int = Field(default=20, ge=1, le=1_000)
    max_history_chars: int = Field(default=20_000, ge=100, le=1_000_000)
    max_dependencies: int = Field(default=1_000, ge=1, le=10_000)
    max_provenance_sources: int = Field(default=1_000, ge=1, le=10_000)

    @model_validator(mode="after")
    def validate_signals(self) -> MemoryTaintPolicy:
        if self.privileged_signals & self.non_overridable_signals:
            raise ValueError("privileged and non-overridable signals must be disjoint")
        return self
