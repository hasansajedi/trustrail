"""Typed contracts for sensitive-data flow across agents and tools."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.data_labels import (
    data_label_digest,
    data_label_reference,
)
from trustrail.models.data_lifecycle import DataClassification
from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_REFERENCE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_SIGNATURE_PATTERN = r"^[0-9a-f]{128}$"


def _aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class SensitiveDataSurface(StrEnum):
    """Agent surfaces across which sensitivity metadata must travel."""

    PROMPT = "prompt"
    MODEL_OUTPUT = "model_output"
    STRUCTURED_EXTRACTION = "structured_extraction"
    RETRIEVAL_DOCUMENT = "retrieval_document"
    RETRIEVAL_CONTEXT = "retrieval_context"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    TOOL_ARGUMENT = "tool_argument"
    TOOL_RESULT = "tool_result"
    AGENT_MESSAGE = "agent_message"
    STREAM_FRAGMENT = "stream_fragment"
    DERIVED_ARTIFACT = "derived_artifact"


class DataFlowTransformation(StrEnum):
    """Declared semantic or representational data transformations."""

    ORIGIN = "origin"
    MODEL_GENERATE = "model_generate"
    STRUCTURED_EXTRACT = "structured_extract"
    RETRIEVE = "retrieve"
    SUMMARIZE = "summarize"
    ENCODE = "encode"
    DECODE = "decode"
    CHUNK = "chunk"
    AGGREGATE = "aggregate"
    INDIRECT_REFERENCE = "indirect_reference"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    MEMORY_STORE = "memory_store"
    MEMORY_RECALL = "memory_recall"
    AGENT_TRANSFER = "agent_transfer"
    STREAM = "stream"
    DECLASSIFY = "declassify"


class SensitiveDataSink(StrEnum):
    """Security-relevant sink categories checked before disclosure."""

    NETWORK = "network"
    MESSAGE = "message"
    FILE = "file"
    LOG = "log"
    MODEL = "model"
    MEMORY = "memory"
    TENANT = "tenant"
    MCP_SERVER = "mcp_server"
    TOOL = "tool"


class SensitiveDataFlowCode(StrEnum):
    """Stable outcomes for propagation and sink authorization."""

    ALLOWED = "allowed"
    LABEL_MISSING = "label_missing"
    LABEL_KEY_UNKNOWN = "label_key_unknown"
    LABEL_SIGNATURE_INVALID = "label_signature_invalid"
    LABEL_NOT_YET_VALID = "label_not_yet_valid"
    LABEL_EXPIRED = "label_expired"
    CONTENT_BINDING_INVALID = "content_binding_invalid"
    TENANT_CONFLICT = "tenant_conflict"
    USER_CONFLICT = "user_conflict"
    PURPOSE_DENIED = "purpose_denied"
    SINK_DENIED = "sink_denied"
    LINEAGE_MISSING = "lineage_missing"
    LINEAGE_MISMATCH = "lineage_mismatch"
    POLICY_EXPANSION = "policy_expansion"
    DECLASSIFICATION_REQUIRED = "declassification_required"
    DECLASSIFICATION_INVALID = "declassification_invalid"
    DECLASSIFICATION_EXPIRED = "declassification_expired"
    LINEAGE_LIMIT_EXCEEDED = "lineage_limit_exceeded"


class SensitiveDataFlowTrustedKey(BaseModel):
    """Out-of-band authority for labels or declassification grants."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    public_key: bytes = Field(min_length=32, max_length=32, exclude=True, repr=False)
    allowed_tenant_ids: frozenset[str] = Field(min_length=1, max_length=10_000)
    can_declassify: bool = False
    active_from: datetime | None = None
    expires_at: datetime | None = None
    revoked: bool = False

    @field_validator("active_from", "expires_at")
    @classmethod
    def timestamps_are_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return value if value is None else _aware(value, info.field_name)

    @field_validator("allowed_tenant_ids")
    @classmethod
    def tenants_are_valid(cls, values: frozenset[str]) -> frozenset[str]:
        if any(re.fullmatch(_IDENTIFIER_PATTERN, value) is None for value in values):
            raise ValueError("allowed tenant IDs contain an invalid identifier")
        return values

    @model_validator(mode="after")
    def lifetime_is_ordered(self) -> SensitiveDataFlowTrustedKey:
        if self.active_from and self.expires_at and self.expires_at <= self.active_from:
            raise ValueError("expires_at must be after active_from")
        return self

    @property
    def key_id(self) -> str:
        return data_label_reference(self.public_key)


class SensitiveDataFlowLabel(BaseModel):
    """Signed, content-bound authority that follows sensitive data."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    label_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issuer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    key_id: str = Field(pattern=_REFERENCE_PATTERN)
    artifact_ref: str = Field(pattern=_REFERENCE_PATTERN)
    surface: SensitiveDataSurface
    content_digest: str = Field(pattern=_DIGEST_PATTERN)
    origin_refs: frozenset[str] = Field(min_length=1, max_length=10_000)
    origin_trust_domains: frozenset[str] = Field(min_length=1, max_length=1_000)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    user_ref: str = Field(pattern=_REFERENCE_PATTERN)
    allowed_purpose_ids: frozenset[str] = Field(min_length=1, max_length=1_000)
    sensitivity: DataClassification
    allowed_sink_kinds: frozenset[SensitiveDataSink] = Field(min_length=1)
    allowed_sink_ids: frozenset[str] = Field(min_length=1, max_length=10_000)
    source_label_digests: tuple[str, ...] = Field(default=(), max_length=10_000)
    ancestor_label_digests: tuple[str, ...] = Field(default=(), max_length=10_000)
    transformations_seen: frozenset[DataFlowTransformation] = Field(min_length=1)
    last_transformation: DataFlowTransformation
    lineage_depth: int = Field(ge=0, le=128)
    declassification_grant_digests: tuple[str, ...] = Field(default=(), max_length=1_000)
    issued_at: datetime
    expires_at: datetime
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator("origin_trust_domains", "allowed_purpose_ids", "allowed_sink_ids")
    @classmethod
    def identifiers_are_valid(cls, values: frozenset[str]) -> frozenset[str]:
        if any(re.fullmatch(_IDENTIFIER_PATTERN, value) is None for value in values):
            raise ValueError("flow metadata contains an invalid identifier")
        return values

    @field_validator("origin_refs")
    @classmethod
    def origin_references_are_valid(cls, values: frozenset[str]) -> frozenset[str]:
        if any(re.fullmatch(_REFERENCE_PATTERN, value) is None for value in values):
            raise ValueError("origin_refs must contain one-way SHA-256 references")
        return values

    @field_validator(
        "source_label_digests",
        "ancestor_label_digests",
        "declassification_grant_digests",
    )
    @classmethod
    def digests_are_sorted(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(_DIGEST_PATTERN, value) is None for value in values):
            raise ValueError("lineage values must be SHA-256 digests")
        if tuple(sorted(set(values))) != values:
            raise ValueError("lineage values must be unique and sorted")
        return values

    @field_validator("issued_at", "expires_at")
    @classmethod
    def label_timestamps_are_aware(cls, value: datetime, info: Any) -> datetime:
        return _aware(value, info.field_name)

    @model_validator(mode="after")
    def lineage_is_consistent(self) -> SensitiveDataFlowLabel:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        is_origin = self.last_transformation == DataFlowTransformation.ORIGIN
        if is_origin != (self.lineage_depth == 0 and not self.source_label_digests):
            raise ValueError("origin and derived lineage shape is inconsistent")
        if not set(self.source_label_digests).issubset(self.ancestor_label_digests):
            raise ValueError("all source labels must appear in ancestor lineage")
        if self.last_transformation not in self.transformations_seen:
            raise ValueError("last transformation must be included in transformations_seen")
        if (
            self.last_transformation == DataFlowTransformation.DECLASSIFY
            and not self.declassification_grant_digests
        ):
            raise ValueError("declassification requires a grant binding")
        return self

    @property
    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="python", exclude={"signature"})

    @property
    def signing_bytes(self) -> bytes:
        from trustrail.models.data_labels import canonical_data_label_json

        return canonical_data_label_json(self.signing_payload).encode()

    @property
    def label_digest(self) -> str:
        return data_label_digest({"payload": self.signing_payload, "signature": self.signature})


class SensitiveDataDerivationRequest(BaseModel):
    """Request to label transformed, combined, chunked, or indirect data."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    label_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    artifact_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    surface: SensitiveDataSurface
    content_digest: str = Field(pattern=_DIGEST_PATTERN)
    source_labels: tuple[SensitiveDataFlowLabel, ...] = Field(min_length=1, max_length=10_000)
    transformation: DataFlowTransformation
    issued_at: datetime

    @field_validator("issued_at")
    @classmethod
    def issued_at_is_aware(cls, value: datetime) -> datetime:
        return _aware(value, "issued_at")

    @model_validator(mode="after")
    def transformation_is_derived(self) -> SensitiveDataDerivationRequest:
        if self.transformation in {
            DataFlowTransformation.ORIGIN,
            DataFlowTransformation.DECLASSIFY,
        }:
            raise ValueError("derivation requires a non-origin, non-declassification transform")
        return self


class DeclassificationGrant(BaseModel):
    """Independent signed authority for one exact sensitivity reduction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    grant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issuer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    key_id: str = Field(pattern=_REFERENCE_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    user_ref: str = Field(pattern=_REFERENCE_PATTERN)
    source_label_digest: str = Field(pattern=_DIGEST_PATTERN)
    output_content_digest: str = Field(pattern=_DIGEST_PATTERN)
    target_sensitivity: DataClassification
    allowed_purpose_ids: frozenset[str] = Field(min_length=1, max_length=1_000)
    allowed_sink_kinds: frozenset[SensitiveDataSink] = Field(min_length=1)
    allowed_sink_ids: frozenset[str] = Field(min_length=1, max_length=10_000)
    justification_ref: str = Field(pattern=_REFERENCE_PATTERN)
    issued_at: datetime
    expires_at: datetime
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator("allowed_purpose_ids", "allowed_sink_ids")
    @classmethod
    def grant_identifiers_are_valid(cls, values: frozenset[str]) -> frozenset[str]:
        if any(re.fullmatch(_IDENTIFIER_PATTERN, value) is None for value in values):
            raise ValueError("declassification metadata contains an invalid identifier")
        return values

    @field_validator("issued_at", "expires_at")
    @classmethod
    def grant_timestamps_are_aware(cls, value: datetime, info: Any) -> datetime:
        return _aware(value, info.field_name)

    @model_validator(mode="after")
    def grant_lifetime_is_ordered(self) -> DeclassificationGrant:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self

    @property
    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="python", exclude={"signature"})

    @property
    def signing_bytes(self) -> bytes:
        from trustrail.models.data_labels import canonical_data_label_json

        return canonical_data_label_json(self.signing_payload).encode()

    @property
    def grant_digest(self) -> str:
        return data_label_digest({"payload": self.signing_payload, "signature": self.signature})


class SensitiveDataDeclassificationRequest(BaseModel):
    """Exact output and metadata proposed under a declassification grant."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    label_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    artifact_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    surface: SensitiveDataSurface
    source_label: SensitiveDataFlowLabel
    output_content_digest: str = Field(pattern=_DIGEST_PATTERN)
    grant: DeclassificationGrant
    issued_at: datetime

    @field_validator("issued_at")
    @classmethod
    def declassification_time_is_aware(cls, value: datetime) -> datetime:
        return _aware(value, "issued_at")


class SensitiveDataDestination(BaseModel):
    """Authenticated sink identity and tenant boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sink_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    sink_kind: SensitiveDataSink
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)


class SensitiveDataTransferRequest(BaseModel):
    """Exact sensitive-data disclosure proposed at a sink."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    label: SensitiveDataFlowLabel | None
    source_labels: tuple[SensitiveDataFlowLabel, ...] = Field(default=(), max_length=10_000)
    declassification_grants: tuple[DeclassificationGrant, ...] = Field(default=(), max_length=1_000)
    content_digest: str = Field(pattern=_DIGEST_PATTERN)
    authenticated_tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    authenticated_user_ref: str = Field(pattern=_REFERENCE_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    destination: SensitiveDataDestination

    @property
    def request_digest(self) -> str:
        return data_label_digest(self)


class SensitiveDataFlowFinding(BaseModel):
    """Content-free explanation of a flow decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: SensitiveDataFlowCode
    severity: Severity
    message: str


class SensitiveDataFlowEvidence(BaseModel):
    """Hashed evidence for an evaluated flow without raw identifiers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    label_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    sink_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    lineage_depth: int = Field(ge=0, le=128)
    origin_count: int = Field(ge=0, le=10_000)
    source_count: int = Field(ge=0, le=10_000)
    sensitivity: DataClassification | None = None
    transformation: DataFlowTransformation | None = None


class AuthorizedSensitiveDataTransfer(BaseModel):
    """Content-free permit for one exact sink request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(pattern=_DIGEST_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    label_digest: str = Field(pattern=_DIGEST_PATTERN)
    sink_ref: str = Field(pattern=_REFERENCE_PATTERN)
    sink_kind: SensitiveDataSink


class SensitiveDataFlowAuditEvent(BaseModel):
    """Metadata-only audit event for propagation and sink enforcement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: SensitiveDataFlowCode
    action: GuardAction
    request_ref: str = Field(pattern=_REFERENCE_PATTERN)
    label_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    sink_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def audit_time_is_aware(cls, value: datetime) -> datetime:
        return _aware(value, "occurred_at")


class SensitiveDataFlowDecision(BaseModel):
    """Result from propagation, declassification, or sink authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: GuardAction
    findings: tuple[SensitiveDataFlowFinding, ...] = ()
    derived_label: SensitiveDataFlowLabel | None = None
    permit: AuthorizedSensitiveDataTransfer | None = None
    evidence: SensitiveDataFlowEvidence
    audit_event: SensitiveDataFlowAuditEvent

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW
