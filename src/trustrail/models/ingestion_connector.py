"""Typed contracts for admission and continuous verification of ingestion connectors."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity
from trustrail.models.supply_chain import ArtifactDigest

_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$"
_DIGEST = r"^[0-9a-f]{64}$"
_KEY_ID = r"^sha256:[0-9a-f]{64}$"
_SIGNATURE = r"^[0-9a-f]{128}$"
_CONTENT_TYPE = r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+*/-]{0,126}$"


def _aware(value: datetime, field_name: str) -> datetime:
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
        return _canonicalize({name: getattr(value, name) for name in value.__class__.model_fields})
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


def canonical_connector_json(value: Any) -> str:
    """Serialize connector security data using the signing profile."""
    return json.dumps(
        _canonicalize(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def connector_digest(value: Any) -> str:
    """Return a stable SHA-256 digest for connector security data."""
    return hashlib.sha256(canonical_connector_json(value).encode()).hexdigest()


def connector_reference(
    value: str,
    *,
    domain: Literal["artifact", "connector", "document", "generic", "sync"] = "generic",
) -> str:
    """Return a domain-separated one-way reference for findings and lineage."""
    payload = f"trustrail:ingestion:{domain}:{value}".encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _validate_uri(value: str) -> str:
    if any(ord(character) < 32 for character in value) or "\\" in value:
        raise ValueError("source URI contains unsafe characters")
    parsed = urlsplit(value)
    if not parsed.scheme or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("source URI requires a scheme and cannot contain credentials or fragments")
    if parsed.scheme != "file" and not parsed.hostname:
        raise ValueError("remote source URI requires a hostname")
    return value


class IngestionConnectorKind(StrEnum):
    """Security-sensitive ingestion component types."""

    DOCUMENT_LOADER = "document_loader"
    PARSER = "parser"
    OCR = "ocr"
    CRAWLER = "crawler"
    FEED = "feed"
    SYNCHRONIZER = "synchronizer"


class IngestionConnectorStatus(StrEnum):
    """Control-plane lifecycle state for a connector."""

    ACTIVE = "active"
    COMPROMISED = "compromised"
    REVOKED = "revoked"


class ConnectorSandboxControl(StrEnum):
    """Externally enforced isolation controls required by a manifest."""

    PROCESS_ISOLATION = "process_isolation"
    READ_ONLY_ROOT = "read_only_root"
    EPHEMERAL_WORKSPACE = "ephemeral_workspace"
    NETWORK_ALLOWLIST = "network_allowlist"
    NO_HOST_SECRETS = "no_host_secrets"
    RESOURCE_LIMITS = "resource_limits"


class ConnectorAdmissionControl(StrEnum):
    """Independent evidence categories required before admission."""

    ARTIFACT_INTEGRITY = "artifact_integrity"
    DEPENDENCY_POLICY = "dependency_policy"
    SANDBOX = "sandbox"
    LEAST_PRIVILEGE = "least_privilege"
    SOURCE_OWNERSHIP = "source_ownership"


class ConnectorSyncStatus(StrEnum):
    """Terminal connector synchronization outcomes."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class IngestionConnectorPhase(StrEnum):
    """Lifecycle boundary that produced a connector decision."""

    ADMISSION = "admission"
    SYNCHRONIZATION = "synchronization"
    DOCUMENT = "document"
    COMPLETION = "completion"
    DOWNSTREAM = "downstream"
    INCIDENT = "incident"


class IngestionConnectorCode(StrEnum):
    """Stable connector admission, drift, provenance, and quarantine codes."""

    MANIFEST_UNSIGNED = "manifest_unsigned"
    MANIFEST_KEY_UNKNOWN = "manifest_key_unknown"
    MANIFEST_KEY_INACTIVE = "manifest_key_inactive"
    MANIFEST_SIGNATURE_INVALID = "manifest_signature_invalid"
    MANIFEST_NOT_YET_VALID = "manifest_not_yet_valid"
    MANIFEST_EXPIRED = "manifest_expired"
    CONNECTOR_COMPROMISED = "connector_compromised"
    CONNECTOR_REVOKED = "connector_revoked"
    EVIDENCE_REQUIRED = "evidence_required"
    EVIDENCE_KEY_UNKNOWN = "evidence_key_unknown"
    EVIDENCE_KEY_INACTIVE = "evidence_key_inactive"
    EVIDENCE_SIGNATURE_INVALID = "evidence_signature_invalid"
    EVIDENCE_STALE = "evidence_stale"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    ADMISSION_CONTROL_MISSING = "admission_control_missing"
    SOURCE_OWNERSHIP_UNVERIFIED = "source_ownership_unverified"
    ADMISSION_INVALID = "admission_invalid"
    EFFECTIVE_STATE_DRIFT = "effective_state_drift"
    SOURCE_NOT_ALLOWED = "source_not_allowed"
    SCHEDULE_INVALID = "schedule_invalid"
    AUTHORIZATION_INVALID = "authorization_invalid"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    AUTHORIZATION_REPLAYED = "authorization_replayed"
    DOCUMENT_LIMIT_EXCEEDED = "document_limit_exceeded"
    DOCUMENT_TOO_LARGE = "document_too_large"
    CONTENT_TYPE_UNEXPECTED = "content_type_unexpected"
    PARSER_AMBIGUOUS = "parser_ambiguous"
    PARSER_MISMATCH = "parser_mismatch"
    CONTENT_INTEGRITY_MISMATCH = "content_integrity_mismatch"
    PROVENANCE_MISSING = "provenance_missing"
    PROVENANCE_INVALID = "provenance_invalid"
    PARTIAL_SYNC = "partial_sync"
    SYNC_REPORT_INVALID = "sync_report_invalid"
    LINEAGE_UNAVAILABLE = "lineage_unavailable"
    ARTIFACT_QUARANTINED = "artifact_quarantined"


class ConnectorArtifactIdentity(BaseModel):
    """Exact publisher, artifact, dependency, revision, and integrity identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: str = Field(pattern=_IDENTIFIER)
    publisher: str = Field(pattern=_IDENTIFIER)
    source_uri: str = Field(min_length=1, max_length=2_048)
    revision: str = Field(pattern=_IDENTIFIER)
    artifact_digest: ArtifactDigest
    dependency_lock_digest: str = Field(pattern=_DIGEST)

    @field_validator("source_uri")
    @classmethod
    def validate_source_uri(cls, value: str) -> str:
        return _validate_uri(value)


class ConnectorParserIdentity(BaseModel):
    """Pinned parser implementation and extraction configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    parser_id: str = Field(pattern=_IDENTIFIER)
    version: str = Field(pattern=_IDENTIFIER)
    implementation_digest: str = Field(pattern=_DIGEST)
    configuration_digest: str = Field(pattern=_DIGEST)


class ConnectorTransformIdentity(BaseModel):
    """One ordered, pinned ingestion transformation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    transform_id: str = Field(pattern=_IDENTIFIER)
    version: str = Field(pattern=_IDENTIFIER)
    implementation_digest: str = Field(pattern=_DIGEST)
    configuration_digest: str = Field(pattern=_DIGEST)


class ConnectorSchedule(BaseModel):
    """Application-owned schedule identity and interval."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schedule_id: str = Field(pattern=_IDENTIFIER)
    interval_seconds: int = Field(ge=1, le=31_536_000)


class ConnectorNetworkDestination(BaseModel):
    """Exact egress origin allowed for connector execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme: Literal["https", "s3", "gs", "azure"]
    host: str = Field(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
    port: int | None = Field(default=None, ge=1, le=65_535)

    @field_validator("host")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        return value.casefold()


class ConnectorConfiguration(BaseModel):
    """Complete effective connector and parser state pinned by the manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact: ConnectorArtifactIdentity
    parser: ConnectorParserIdentity
    allowed_source_uris: frozenset[str] = Field(min_length=1, max_length=1_000)
    credential_references: frozenset[str] = Field(default_factory=frozenset, max_length=100)
    transforms: tuple[ConnectorTransformIdentity, ...] = Field(default=(), max_length=100)
    schedule: ConnectorSchedule
    network_destinations: tuple[ConnectorNetworkDestination, ...] = Field(
        default=(), max_length=100
    )
    expected_content_types: frozenset[str] = Field(min_length=1, max_length=100)
    granted_scopes: frozenset[str] = Field(default_factory=frozenset, max_length=100)
    sandbox_controls: frozenset[ConnectorSandboxControl] = Field(min_length=1)

    @field_validator("allowed_source_uris")
    @classmethod
    def validate_sources(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(_validate_uri(value) for value in values)

    @field_validator("credential_references", "granted_scopes")
    @classmethod
    def validate_identifiers(cls, values: frozenset[str], info: Any) -> frozenset[str]:
        if any(re.fullmatch(_IDENTIFIER, value) is None for value in values):
            raise ValueError(f"{info.field_name} contains an invalid identifier")
        return values

    @field_validator("expected_content_types")
    @classmethod
    def validate_content_types(cls, values: frozenset[str]) -> frozenset[str]:
        normalized = frozenset(value.casefold() for value in values)
        if any(re.fullmatch(_CONTENT_TYPE, value) is None for value in normalized):
            raise ValueError("expected_content_types contains an invalid media type")
        return normalized

    @model_validator(mode="after")
    def validate_unique_transforms(self) -> ConnectorConfiguration:
        identities = [item.transform_id for item in self.transforms]
        if len(identities) != len(set(identities)):
            raise ValueError("connector transforms must have unique identities")
        if len(self.network_destinations) != len(set(self.network_destinations)):
            raise ValueError("connector network destinations must be unique")
        canonical_connector_json(self)
        return self

    @property
    def configuration_digest(self) -> str:
        return connector_digest(self)


class _SignedConnectorModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    signature: str | None = Field(default=None, pattern=_SIGNATURE)

    @property
    def signing_payload(self) -> dict[str, Any]:
        return {
            name: getattr(self, name) for name in self.__class__.model_fields if name != "signature"
        }

    @property
    def signing_bytes(self) -> bytes:
        return canonical_connector_json(self.signing_payload).encode()

    @property
    def signed_digest(self) -> str:
        return connector_digest({"payload": self.signing_payload, "signature": self.signature})


class IngestionConnectorManifest(_SignedConnectorModel):
    """Publisher-signed complete connector configuration."""

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    manifest_id: str = Field(pattern=_IDENTIFIER)
    connector_id: str = Field(pattern=_IDENTIFIER)
    kind: IngestionConnectorKind
    status: IngestionConnectorStatus = IngestionConnectorStatus.ACTIVE
    configuration: ConnectorConfiguration
    max_documents_per_sync: int = Field(default=10_000, ge=1, le=1_000_000)
    max_document_bytes: int = Field(default=10_000_000, ge=1, le=1_000_000_000)
    authority_id: str = Field(pattern=_IDENTIFIER)
    key_id: str = Field(pattern=_KEY_ID)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_time(cls, value: datetime, info: Any) -> datetime:
        return _aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> IngestionConnectorManifest:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        canonical_connector_json(self.signing_payload)
        return self

    @property
    def manifest_digest(self) -> str:
        return self.signed_digest


class ConnectorTrustedKey(BaseModel):
    """Out-of-band trusted Ed25519 key for connector security evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authority_id: str = Field(pattern=_IDENTIFIER)
    public_key: bytes = Field(min_length=32, max_length=32, exclude=True, repr=False)
    active_from: datetime | None = None
    expires_at: datetime | None = None
    revoked: bool = False

    @field_validator("active_from", "expires_at")
    @classmethod
    def validate_time(cls, value: datetime | None, info: Any) -> datetime | None:
        return None if value is None else _aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> ConnectorTrustedKey:
        if self.active_from and self.expires_at and self.expires_at <= self.active_from:
            raise ValueError("trusted key expires_at must be after active_from")
        return self

    @property
    def key_id(self) -> str:
        return f"sha256:{hashlib.sha256(self.public_key).hexdigest()}"


class ConnectorAdmissionEvidence(_SignedConnectorModel):
    """Independent signed evidence for the exact effective configuration."""

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    evidence_id: str = Field(pattern=_IDENTIFIER)
    connector_id: str = Field(pattern=_IDENTIFIER)
    manifest_digest: str = Field(pattern=_DIGEST)
    configuration: ConnectorConfiguration
    controls: frozenset[ConnectorAdmissionControl] = Field(min_length=1)
    owned_source_uris: frozenset[str] = Field(min_length=1, max_length=1_000)
    authority_id: str = Field(pattern=_IDENTIFIER)
    key_id: str = Field(pattern=_KEY_ID)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_time(cls, value: datetime, info: Any) -> datetime:
        return _aware(value, info.field_name)

    @field_validator("owned_source_uris")
    @classmethod
    def validate_sources(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(_validate_uri(value) for value in values)

    @model_validator(mode="after")
    def validate_lifetime(self) -> ConnectorAdmissionEvidence:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self

    @property
    def evidence_digest(self) -> str:
        return self.signed_digest


class AdmittedIngestionConnector(_SignedConnectorModel):
    """Control-plane admission bound to a manifest and attested configuration."""

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    admission_id: str = Field(pattern=_IDENTIFIER)
    connector_id: str = Field(pattern=_IDENTIFIER)
    manifest_digest: str = Field(pattern=_DIGEST)
    evidence_digest: str = Field(pattern=_DIGEST)
    configuration_digest: str = Field(pattern=_DIGEST)
    authority_id: str = Field(pattern=_IDENTIFIER)
    key_id: str = Field(pattern=_KEY_ID)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_time(cls, value: datetime, info: Any) -> datetime:
        return _aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> AdmittedIngestionConnector:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self

    @property
    def admission_digest(self) -> str:
        return self.signed_digest


class ConnectorEffectiveState(BaseModel):
    """Observed connector state rechecked immediately before every sync."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_id: str = Field(pattern=_IDENTIFIER)
    connector_id: str = Field(pattern=_IDENTIFIER)
    manifest_digest: str = Field(pattern=_DIGEST)
    evidence_digest: str = Field(pattern=_DIGEST)
    configuration: ConnectorConfiguration
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _aware(value, "observed_at")

    @property
    def state_digest(self) -> str:
        return connector_digest(self)


class ConnectorSyncRequest(BaseModel):
    """One scheduled synchronization request and its live effective state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sync_id: str = Field(pattern=_IDENTIFIER)
    connector_id: str = Field(pattern=_IDENTIFIER)
    manifest_digest: str = Field(pattern=_DIGEST)
    source_uris: frozenset[str] = Field(min_length=1, max_length=1_000)
    scheduled_for: datetime
    effective_state: ConnectorEffectiveState

    @field_validator("source_uris")
    @classmethod
    def validate_sources(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(_validate_uri(value) for value in values)

    @field_validator("scheduled_for")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _aware(value, "scheduled_for")

    @property
    def request_digest(self) -> str:
        return connector_digest(self)


class AuthorizedConnectorSync(_SignedConnectorModel):
    """Short-lived authorization for one exact sync and effective state."""

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    authorization_id: str = Field(pattern=_IDENTIFIER)
    sync_id: str = Field(pattern=_IDENTIFIER)
    connector_id: str = Field(pattern=_IDENTIFIER)
    manifest_digest: str = Field(pattern=_DIGEST)
    admission_digest: str = Field(pattern=_DIGEST)
    evidence_digest: str = Field(pattern=_DIGEST)
    configuration_digest: str = Field(pattern=_DIGEST)
    state_digest: str = Field(pattern=_DIGEST)
    request_digest: str = Field(pattern=_DIGEST)
    source_uris: frozenset[str] = Field(min_length=1, max_length=1_000)
    max_documents: int = Field(ge=1)
    max_document_bytes: int = Field(ge=1)
    expected_content_types: frozenset[str] = Field(min_length=1)
    parser: ConnectorParserIdentity
    authority_id: str = Field(pattern=_IDENTIFIER)
    key_id: str = Field(pattern=_KEY_ID)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def validate_time(cls, value: datetime, info: Any) -> datetime:
        return _aware(value, info.field_name)

    @model_validator(mode="after")
    def validate_lifetime(self) -> AuthorizedConnectorSync:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self

    @property
    def authorization_digest(self) -> str:
        return self.signed_digest


class ConnectorDocumentProvenance(_SignedConnectorModel):
    """Signed binding from document bytes to connector, parser, source, and sync."""

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    document_reference: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    content_digest: ArtifactDigest
    content_type: str = Field(pattern=_CONTENT_TYPE)
    source_uri: str = Field(min_length=1, max_length=2_048)
    connector_reference: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    sync_reference: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    connector_id: str = Field(pattern=_IDENTIFIER)
    sync_id: str = Field(pattern=_IDENTIFIER)
    manifest_digest: str = Field(pattern=_DIGEST)
    configuration_digest: str = Field(pattern=_DIGEST)
    state_digest: str = Field(pattern=_DIGEST)
    parser: ConnectorParserIdentity
    produced_at: datetime
    authority_id: str = Field(pattern=_IDENTIFIER)
    key_id: str = Field(pattern=_KEY_ID)

    @field_validator("source_uri")
    @classmethod
    def validate_source(cls, value: str) -> str:
        return _validate_uri(value)

    @field_validator("produced_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _aware(value, "produced_at")

    @property
    def provenance_digest(self) -> str:
        return self.signed_digest


class ConnectorDocument(BaseModel):
    """Document bytes plus optional signed connector provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    document_id: str = Field(pattern=_IDENTIFIER)
    content: str | bytes = Field(exclude=True, repr=False)
    source_uri: str = Field(min_length=1, max_length=2_048)
    content_type: str = Field(pattern=_CONTENT_TYPE)
    parser_candidates: tuple[ConnectorParserIdentity, ...] = Field(max_length=8)
    observed_digest: ArtifactDigest
    provenance: ConnectorDocumentProvenance | None = None

    @field_validator("source_uri")
    @classmethod
    def validate_source(cls, value: str) -> str:
        return _validate_uri(value)

    @field_validator("content_type")
    @classmethod
    def normalize_content_type(cls, value: str) -> str:
        return value.casefold()

    @classmethod
    def from_content(
        cls,
        *,
        document_id: str,
        content: str | bytes,
        source_uri: str,
        content_type: str,
        parser_candidates: tuple[ConnectorParserIdentity, ...],
    ) -> ConnectorDocument:
        payload = content.encode() if isinstance(content, str) else content
        return cls(
            document_id=document_id,
            content=content,
            source_uri=source_uri,
            content_type=content_type,
            parser_candidates=parser_candidates,
            observed_digest=ArtifactDigest.from_bytes(payload),
        )


class ConnectorSyncReport(BaseModel):
    """Terminal report used to detect partial or inconsistent synchronizations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_id: str = Field(pattern=_IDENTIFIER)
    sync_id: str = Field(pattern=_IDENTIFIER)
    manifest_digest: str = Field(pattern=_DIGEST)
    state_digest: str = Field(pattern=_DIGEST)
    status: ConnectorSyncStatus
    expected_documents: int = Field(ge=0, le=1_000_000)
    processed_documents: int = Field(ge=0, le=1_000_000)
    failure_count: int = Field(ge=0, le=1_000_000)
    completed_at: datetime

    @field_validator("completed_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        return _aware(value, "completed_at")


class IngestionConnectorPolicy(BaseModel):
    """Freshness, scheduling, and admission requirements."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_manifest_age_seconds: int = Field(default=86_400, ge=1, le=31_536_000)
    max_evidence_age_seconds: int = Field(default=3_600, ge=1, le=604_800)
    admission_ttl_seconds: int = Field(default=3_600, ge=1, le=604_800)
    authorization_ttl_seconds: int = Field(default=900, ge=1, le=86_400)
    schedule_skew_seconds: int = Field(default=300, ge=0, le=86_400)
    clock_skew_seconds: int = Field(default=5, ge=0, le=300)
    required_controls: frozenset[ConnectorAdmissionControl] = Field(
        default_factory=lambda: frozenset(ConnectorAdmissionControl)
    )


class IngestionConnectorFinding(BaseModel):
    """Content-free connector verification finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: IngestionConnectorCode
    severity: Severity
    message: str
    connector_reference: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")


class IngestionConnectorDecision(BaseModel):
    """Admission, sync, document, completion, or quarantine decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: IngestionConnectorPhase
    action: GuardAction
    findings: tuple[IngestionConnectorFinding, ...] = ()
    admission: AdmittedIngestionConnector | None = None
    authorization: AuthorizedConnectorSync | None = None
    document: ConnectorDocument | None = None
    affected_artifact_references: tuple[str, ...] = Field(default=(), max_length=100_000)
    impact_truncated: bool = False

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW

    @property
    def is_quarantined(self) -> bool:
        return self.action in {GuardAction.BLOCK, GuardAction.QUARANTINE}
