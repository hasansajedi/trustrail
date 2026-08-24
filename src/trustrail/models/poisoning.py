"""Typed models for data and model poisoning controls."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from trustrail.models.enums import GuardAction, Severity, TrustLevel
from trustrail.models.supply_chain import ArtifactDigest


class DataAssetKind(StrEnum):
    """Data-bearing assets that can influence model behavior."""

    TRAINING_DATA = "training_data"
    FINE_TUNING_DATA = "fine_tuning_data"
    RAG_DOCUMENT = "rag_document"
    MEMORY = "memory"
    METADATA = "metadata"
    MODEL_ARTIFACT = "model_artifact"


class PoisoningCode(StrEnum):
    """Stable machine-readable poisoning and policy outcomes."""

    UNKNOWN_SOURCE = "unknown_source"
    KIND_NOT_ALLOWED = "kind_not_allowed"
    TRUST_MISMATCH = "trust_mismatch"
    VERSION_NOT_ALLOWED = "version_not_allowed"
    UNPINNED_VERSION = "unpinned_version"
    AUTHORIZATION_MISSING = "authorization_missing"
    WRITER_NOT_AUTHORIZED = "writer_not_authorized"
    TENANT_NOT_AUTHORIZED = "tenant_not_authorized"
    PURPOSE_NOT_AUTHORIZED = "purpose_not_authorized"
    CONTENT_INTEGRITY_MISMATCH = "content_integrity_mismatch"
    EXPECTED_DIGEST_MISSING = "expected_digest_missing"
    EXPECTED_DIGEST_MISMATCH = "expected_digest_mismatch"
    BROKEN_TRANSFORMATION_LINEAGE = "broken_transformation_lineage"
    CONTENT_SCAN_LIMIT_EXCEEDED = "content_scan_limit_exceeded"
    SUSPICIOUS_INSTRUCTION = "suspicious_instruction"
    SUSPICIOUS_METADATA = "suspicious_metadata"
    ANOMALY_THRESHOLD_EXCEEDED = "anomaly_threshold_exceeded"
    CUSTOM_DETECTOR = "custom_detector"


class DataTransformation(BaseModel):
    """One integrity-linked transformation in a data asset's lineage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=128)
    actor_id: str = Field(min_length=1, max_length=256)
    input_digest: ArtifactDigest
    output_digest: ArtifactDigest


class DataProvenance(BaseModel):
    """Application-assigned origin, version, trust, and transformation history."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
    source_uri: str = Field(min_length=1, max_length=2_048)
    version: str = Field(min_length=1, max_length=256)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    transformations: tuple[DataTransformation, ...] = ()


class IngestionAuthorization(BaseModel):
    """Identity claims to check against trusted application policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    writer_id: str = Field(min_length=1, max_length=256)
    tenant_id: str | None = Field(default=None, max_length=256)
    purpose: str | None = Field(default=None, max_length=128)


class DataIngestionRecord(BaseModel):
    """A data asset and its security evidence at an ingestion boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    item_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
    kind: DataAssetKind
    content: str | bytes
    provenance: DataProvenance
    authorization: IngestionAuthorization | None = None
    observed_digest: ArtifactDigest
    metadata: dict[str, Any] = Field(default_factory=dict)
    anomaly_score: float | None = Field(default=None, ge=0.0, le=1.0)

    @classmethod
    def from_content(
        cls,
        *,
        item_id: str,
        kind: DataAssetKind,
        content: str | bytes,
        provenance: DataProvenance,
        authorization: IngestionAuthorization | None = None,
        metadata: dict[str, Any] | None = None,
        anomaly_score: float | None = None,
    ) -> DataIngestionRecord:
        """Create a record with a SHA-256 digest of the boundary bytes."""
        payload = content.encode() if isinstance(content, str) else content
        return cls(
            item_id=item_id,
            kind=kind,
            content=content,
            provenance=provenance,
            authorization=authorization,
            observed_digest=ArtifactDigest.from_bytes(payload),
            metadata=metadata or {},
            anomaly_score=anomaly_score,
        )


class DataSourcePolicy(BaseModel):
    """Trusted control-plane policy for one ingestion source."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
    source_uri: str = Field(min_length=1, max_length=2_048)
    allowed_kinds: frozenset[DataAssetKind] = Field(min_length=1)
    trust_level: TrustLevel
    authorized_writers: frozenset[str] = Field(min_length=1)
    allowed_tenants: frozenset[str] | None = None
    allowed_purposes: frozenset[str] | None = None
    allowed_versions: frozenset[str] | None = None
    require_pinned_version: bool = True


def _digest_pinned_kinds() -> frozenset[DataAssetKind]:
    return frozenset(
        {
            DataAssetKind.TRAINING_DATA,
            DataAssetKind.FINE_TUNING_DATA,
            DataAssetKind.MODEL_ARTIFACT,
        }
    )


class DataPoisoningPolicy(BaseModel):
    """Fail-closed controls for data entering model or persistent context."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sources: tuple[DataSourcePolicy, ...] = Field(min_length=1)
    require_authorization: bool = True
    require_expected_digest_for: frozenset[DataAssetKind] = Field(
        default_factory=_digest_pinned_kinds
    )
    expected_digests: dict[str, ArtifactDigest] = Field(default_factory=dict)
    anomaly_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    scan_metadata: bool = True
    max_scan_chars: int = Field(default=100_000, ge=1, le=10_000_000)
    max_metadata_depth: int = Field(default=8, ge=1, le=64)
    max_metadata_nodes: int = Field(default=1_000, ge=1, le=100_000)

    @model_validator(mode="after")
    def validate_unique_sources(self) -> DataPoisoningPolicy:
        source_ids = [source.source_id for source in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("Data poisoning policy contains duplicate source IDs")
        return self


class PoisoningFinding(BaseModel):
    """Content-free explanation of a poisoning decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: PoisoningCode
    severity: Severity
    message: str
    detector_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class DataPoisoningResult(BaseModel):
    """Allow, warn, or quarantine decision for one ingestion record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    item_id: str
    source_id: str
    action: GuardAction
    findings: tuple[PoisoningFinding, ...] = ()

    @property
    def is_quarantined(self) -> bool:
        """Return whether the asset must be kept out of downstream systems."""
        return self.action in (GuardAction.BLOCK, GuardAction.QUARANTINE)

    @property
    def is_allowed(self) -> bool:
        """Return whether the asset may continue through the pipeline."""
        return not self.is_quarantined
