"""Typed contracts for end-to-end GenAI data-classification labels."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.data_lifecycle import DataClassification
from trustrail.models.enums import GuardAction, Severity

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_REFERENCE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_KEY_ID_PATTERN = _REFERENCE_PATTERN
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
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = unicodedata.normalize("NFC", str(key))
            if normalized_key in normalized:
                raise ValueError("keys must remain unique after Unicode normalization")
            normalized[normalized_key] = _canonicalize(item)
        return normalized
    if isinstance(value, (set, frozenset)):
        items = [_canonicalize(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    return value


def canonical_data_label_json(value: Any) -> str:
    """Serialize label data with a deterministic signing profile."""
    return json.dumps(
        _canonicalize(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def data_label_digest(value: Any) -> str:
    """Return a canonical SHA-256 digest."""
    return hashlib.sha256(canonical_data_label_json(value).encode()).hexdigest()


def data_label_reference(value: str | bytes) -> str:
    """Return a one-way reference suitable for content-safe evidence."""
    raw = value.encode() if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


class DataFlowSurface(StrEnum):
    """Surfaces across which a classification label must be preserved."""

    PROMPT = "prompt"
    RETRIEVED_DOCUMENT = "retrieved_document"
    RETRIEVAL_CONTEXT = "retrieval_context"
    EMBEDDING = "embedding"
    CACHE_ENTRY = "cache_entry"
    MODEL_OUTPUT = "model_output"
    TOOL_ARGUMENT = "tool_argument"
    TOOL_RESULT = "tool_result"
    PERSISTED_ARTIFACT = "persisted_artifact"
    LOG_RECORD = "log_record"
    DERIVED_ARTIFACT = "derived_artifact"


class DataBoundaryKind(StrEnum):
    """Completely mediated destinations for labeled data."""

    PROVIDER_CALL = "provider_call"
    RETRIEVAL_ASSEMBLY = "retrieval_assembly"
    PERSISTENCE = "persistence"
    LOGGING = "logging"
    TOOL_INVOCATION = "tool_invocation"
    OUTPUT_DELIVERY = "output_delivery"


class DataTransformationKind(StrEnum):
    """Declared transformations that create a derived label."""

    ORIGIN = "origin"
    COMBINE = "combine"
    TRANSFORM = "transform"
    SUMMARIZE = "summarize"
    EMBED = "embed"
    CACHE = "cache"
    TOOL_RESULT = "tool_result"


class DataHandlingRequirement(StrEnum):
    """Additive controls required by a label at every destination."""

    ENCRYPT_IN_TRANSIT = "encrypt_in_transit"
    ENCRYPT_AT_REST = "encrypt_at_rest"
    REDACT_LOGS = "redact_logs"
    TOKENIZE_IDENTIFIERS = "tokenize_identifiers"
    NO_TRAINING = "no_training"


class DataLabelCode(StrEnum):
    """Stable machine-readable propagation and boundary findings."""

    ALLOWED = "allowed"
    LABEL_MISSING = "label_missing"
    LABEL_UNSIGNED = "label_unsigned"
    LABEL_KEY_UNKNOWN = "label_key_unknown"
    LABEL_ISSUER_MISMATCH = "label_issuer_mismatch"
    LABEL_SIGNATURE_INVALID = "label_signature_invalid"
    LABEL_EXPIRED = "label_expired"
    LABEL_FORGED = "label_forged"
    CONTENT_BINDING_INVALID = "content_binding_invalid"
    TENANT_CONFLICT = "tenant_conflict"
    LABEL_CONFLICT = "label_conflict"
    LABEL_DOWNGRADED = "label_downgraded"
    LINEAGE_MISSING = "lineage_missing"
    LINEAGE_MISMATCH = "lineage_mismatch"
    PURPOSE_DENIED = "purpose_denied"
    RESIDENCY_DENIED = "residency_denied"
    DESTINATION_DENIED = "destination_denied"
    CLASSIFICATION_UNSUPPORTED = "classification_unsupported"
    HANDLING_UNSUPPORTED = "handling_unsupported"
    RETENTION_DENIED = "retention_denied"


class DataClassificationLabel(BaseModel):
    """Ed25519-signed classification and handling authority for exact content."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    label_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issuer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    artifact_ref: str = Field(pattern=_REFERENCE_PATTERN)
    surface: DataFlowSurface
    content_digest: str = Field(pattern=_DIGEST_PATTERN)
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    classification: DataClassification
    allowed_purpose_ids: frozenset[str] = Field(min_length=1, max_length=1_000)
    allowed_residencies: frozenset[str] = Field(min_length=1, max_length=1_000)
    permitted_destination_ids: frozenset[str] = Field(min_length=1, max_length=10_000)
    permitted_boundary_kinds: frozenset[DataBoundaryKind] = Field(
        min_length=1,
        max_length=len(DataBoundaryKind),
    )
    handling_requirements: frozenset[DataHandlingRequirement] = Field(
        default_factory=frozenset,
        max_length=len(DataHandlingRequirement),
    )
    retention_until: datetime
    source_label_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=10_000)
    transformation: DataTransformationKind = DataTransformationKind.ORIGIN
    issued_at: datetime
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @field_validator(
        "allowed_purpose_ids",
        "allowed_residencies",
        "permitted_destination_ids",
    )
    @classmethod
    def validate_identifiers(cls, values: frozenset[str]) -> frozenset[str]:
        if any(re.fullmatch(_IDENTIFIER_PATTERN, value) is None for value in values):
            raise ValueError("label metadata contains an invalid identifier")
        return values

    @field_validator("source_label_digests")
    @classmethod
    def validate_source_digests(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(_DIGEST_PATTERN, value) is None for value in values):
            raise ValueError("source label digests must be SHA-256 values")
        if tuple(sorted(set(values))) != values:
            raise ValueError("source label digests must be unique and sorted")
        return values

    @field_validator("retention_until", "issued_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime, info: Any) -> datetime:
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lineage_shape(self) -> DataClassificationLabel:
        if self.retention_until <= self.issued_at:
            raise ValueError("retention_until must be after issued_at")
        if self.transformation == DataTransformationKind.ORIGIN and self.source_label_digests:
            raise ValueError("origin labels cannot declare source labels")
        if self.transformation != DataTransformationKind.ORIGIN and not self.source_label_digests:
            raise ValueError("derived labels require source label digests")
        return self

    @property
    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="python", exclude={"signature"})

    @property
    def signing_bytes(self) -> bytes:
        return canonical_data_label_json(self.signing_payload).encode()

    @property
    def label_digest(self) -> str:
        return data_label_digest({"payload": self.signing_payload, "signature": self.signature})


class DataLabelTrustedKey(BaseModel):
    """Out-of-band issuer and tenant authority for label verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    public_key: bytes = Field(min_length=32, max_length=32, exclude=True, repr=False)
    allowed_tenant_ids: frozenset[str] = Field(min_length=1, max_length=10_000)
    active_from: datetime | None = None
    expires_at: datetime | None = None
    revoked: bool = False

    @field_validator("allowed_tenant_ids")
    @classmethod
    def validate_tenants(cls, values: frozenset[str]) -> frozenset[str]:
        if any(re.fullmatch(_IDENTIFIER_PATTERN, value) is None for value in values):
            raise ValueError("allowed tenant IDs contain an invalid identifier")
        return values

    @field_validator("active_from", "expires_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime | None, info: Any) -> datetime | None:
        return value if value is None else _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> DataLabelTrustedKey:
        if (
            self.active_from is not None
            and self.expires_at is not None
            and self.expires_at <= self.active_from
        ):
            raise ValueError("trusted key expires_at must be after active_from")
        return self

    @property
    def key_id(self) -> str:
        return data_label_reference(self.public_key)


class DataLabelDestination(BaseModel):
    """Trusted capabilities of one provider, store, logger, tool, or receiver."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    destination_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    boundary_kind: DataBoundaryKind
    tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    residency: str = Field(pattern=_IDENTIFIER_PATTERN)
    supported_classifications: frozenset[DataClassification] = Field(min_length=1, max_length=4)
    enforced_handling: frozenset[DataHandlingRequirement] = Field(
        default_factory=frozenset,
        max_length=len(DataHandlingRequirement),
    )


class DataBoundaryRequest(BaseModel):
    """Exact labeled transfer proposed at one data-flow boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    label: DataClassificationLabel | None
    source_labels: tuple[DataClassificationLabel, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    content_digest: str = Field(pattern=_DIGEST_PATTERN)
    authenticated_tenant_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    purpose_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    destination: DataLabelDestination
    requested_retention_until: datetime | None = None

    @field_validator("requested_retention_until")
    @classmethod
    def require_aware_retention(cls, value: datetime | None) -> datetime | None:
        return value if value is None else _require_aware(value, "requested_retention_until")

    @property
    def request_digest(self) -> str:
        return data_label_digest(self)


class DataLabelJoinRequest(BaseModel):
    """Typed request to conservatively label one derived artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    label_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    artifact_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    surface: DataFlowSurface
    content_digest: str = Field(pattern=_DIGEST_PATTERN)
    source_labels: tuple[DataClassificationLabel, ...] = Field(
        min_length=1,
        max_length=10_000,
    )
    transformation: DataTransformationKind
    issued_at: datetime

    @field_validator("issued_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "issued_at")

    @model_validator(mode="after")
    def reject_origin(self) -> DataLabelJoinRequest:
        if self.transformation == DataTransformationKind.ORIGIN:
            raise ValueError("join requests require a derived transformation")
        return self

    @property
    def request_digest(self) -> str:
        return data_label_digest(self)


class DataLabelFinding(BaseModel):
    """Content-safe explanation of a propagation or boundary decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: DataLabelCode
    severity: Severity
    message: str


class DataLineageEvidence(BaseModel):
    """Content-safe references proving the evaluated lineage shape."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    label_ref: str = Field(pattern=_REFERENCE_PATTERN)
    source_label_refs: tuple[str, ...] = ()
    destination_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    classification: DataClassification
    surface: DataFlowSurface
    transformation: DataTransformationKind


class AuthorizedLabeledTransfer(BaseModel):
    """Content-free permit for one exact boundary request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(pattern=_DIGEST_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    label_digest: str = Field(pattern=_DIGEST_PATTERN)
    destination_ref: str = Field(pattern=_REFERENCE_PATTERN)
    boundary_kind: DataBoundaryKind


class DataLabelAuditEvent(BaseModel):
    """Metadata-only evidence for label joins and boundary checks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: DataLabelCode
    action: GuardAction
    request_ref: str = Field(pattern=_REFERENCE_PATTERN)
    label_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    destination_ref: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    source_count: int = Field(default=0, ge=0, le=10_000)
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _require_aware(value, "occurred_at")


class DataLabelDecision(BaseModel):
    """Decision from conservative joining or boundary authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: GuardAction
    findings: tuple[DataLabelFinding, ...] = ()
    derived_label: DataClassificationLabel | None = None
    permit: AuthorizedLabeledTransfer | None = None
    evidence: DataLineageEvidence | None = None
    audit_event: DataLabelAuditEvent

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW
