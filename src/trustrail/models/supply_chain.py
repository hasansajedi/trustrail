"""Typed AI supply-chain inventory and verification models."""

from __future__ import annotations

import hashlib
import hmac
import json
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity, TrustLevel


class ArtifactKind(StrEnum):
    """Kinds of components that can enter an AI application's supply chain."""

    MODEL = "model"
    DATASET = "dataset"
    PROMPT = "prompt"
    ADAPTER = "adapter"
    PLUGIN = "plugin"
    PACKAGE = "package"
    EXTERNAL_SERVICE = "external_service"
    RETRIEVED_ARTIFACT = "retrieved_artifact"


class ArtifactStatus(StrEnum):
    """Lifecycle state assigned by the application's review process."""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


class DigestAlgorithm(StrEnum):
    """Supported cryptographic artifact digest algorithms."""

    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


class ArtifactVerificationCode(StrEnum):
    """Stable machine-readable artifact verification outcomes."""

    UNKNOWN_ARTIFACT = "unknown_artifact"
    MANIFEST_INTEGRITY_MISMATCH = "manifest_integrity_mismatch"
    KIND_MISMATCH = "kind_mismatch"
    SUPPLIER_MISMATCH = "supplier_mismatch"
    SOURCE_MISMATCH = "source_mismatch"
    REVISION_MISMATCH = "revision_mismatch"
    DIGEST_MISSING = "digest_missing"
    DIGEST_MISMATCH = "digest_mismatch"
    UNPINNED_REVISION = "unpinned_revision"
    UNAPPROVED_ARTIFACT = "unapproved_artifact"
    INSUFFICIENT_TRUST = "insufficient_trust"
    DEPRECATED_ARTIFACT = "deprecated_artifact"
    REVOKED_ARTIFACT = "revoked_artifact"
    LICENSE_MISSING = "license_missing"
    SUPPLIER_NOT_ALLOWED = "supplier_not_allowed"


_DIGEST_LENGTHS = {
    DigestAlgorithm.SHA256: 64,
    DigestAlgorithm.SHA384: 96,
    DigestAlgorithm.SHA512: 128,
}


class ArtifactDigest(BaseModel):
    """A cryptographic digest pinned in an artifact manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: DigestAlgorithm = DigestAlgorithm.SHA256
    value: str

    @field_validator("value")
    @classmethod
    def normalize_digest(cls, value: str) -> str:
        return value.lower()

    @model_validator(mode="after")
    def validate_digest(self) -> ArtifactDigest:
        expected_length = _DIGEST_LENGTHS[self.algorithm]
        if len(self.value) != expected_length or any(
            character not in "0123456789abcdef" for character in self.value
        ):
            raise ValueError(
                f"{self.algorithm.value} digest must be {expected_length} hexadecimal characters"
            )
        return self

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        algorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
    ) -> ArtifactDigest:
        """Calculate a supported digest for an in-memory artifact."""
        return cls(algorithm=algorithm, value=hashlib.new(algorithm.value, payload).hexdigest())

    def matches(self, other: ArtifactDigest) -> bool:
        """Compare digests without data-dependent early exit."""
        return self.algorithm == other.algorithm and hmac.compare_digest(self.value, other.value)


class ArtifactRecord(BaseModel):
    """Approved provenance and integrity metadata for one AI component."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
    kind: ArtifactKind
    supplier: str = Field(min_length=1, max_length=256)
    source_uri: str = Field(min_length=1, max_length=2_048)
    revision: str = Field(min_length=1, max_length=256)
    digest: ArtifactDigest | None = None
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    approved: bool = False
    status: ArtifactStatus = ArtifactStatus.ACTIVE
    license_id: str | None = Field(default=None, max_length=128)
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict)

    @classmethod
    def from_bytes(
        cls,
        *,
        artifact_id: str,
        kind: ArtifactKind,
        supplier: str,
        source_uri: str,
        revision: str,
        payload: bytes,
        algorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
        trust_level: TrustLevel = TrustLevel.UNTRUSTED,
        approved: bool = False,
        status: ArtifactStatus = ArtifactStatus.ACTIVE,
        license_id: str | None = None,
        metadata: dict[str, str | int | float | bool | None] | None = None,
    ) -> ArtifactRecord:
        """Build a manifest record with a digest calculated from trusted bytes."""
        return cls(
            artifact_id=artifact_id,
            kind=kind,
            supplier=supplier,
            source_uri=source_uri,
            revision=revision,
            digest=ArtifactDigest.from_bytes(payload, algorithm),
            trust_level=trust_level,
            approved=approved,
            status=status,
            license_id=license_id,
            metadata=metadata or {},
        )


class ArtifactObservation(BaseModel):
    """Runtime metadata observed before an artifact is loaded or invoked."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
    kind: ArtifactKind
    supplier: str = Field(min_length=1, max_length=256)
    source_uri: str = Field(min_length=1, max_length=2_048)
    revision: str = Field(min_length=1, max_length=256)
    digest: ArtifactDigest | None = None


class ArtifactManifest(BaseModel):
    """Versioned inventory of approved AI supply-chain components."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["trustrail.artifact-manifest.v1"] = "trustrail.artifact-manifest.v1"
    manifest_id: str = Field(min_length=1, max_length=128)
    artifacts: tuple[ArtifactRecord, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_artifact_ids(self) -> ArtifactManifest:
        artifact_ids = [artifact.artifact_id for artifact in self.artifacts]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("Artifact manifest contains duplicate artifact IDs")
        return self

    @property
    def fingerprint_sha256(self) -> str:
        """Return a deterministic fingerprint for out-of-band pinning or signing."""
        canonical = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def matches_fingerprint(self, expected_sha256: str) -> bool:
        """Verify a fingerprint supplied from a trusted, separate channel."""
        return hmac.compare_digest(self.fingerprint_sha256, expected_sha256.lower())


def _digest_required_by_default() -> frozenset[ArtifactKind]:
    return frozenset(kind for kind in ArtifactKind if kind != ArtifactKind.EXTERNAL_SERVICE)


class ArtifactVerificationPolicy(BaseModel):
    """Fail-closed policy applied to manifest records and observations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    minimum_trust: TrustLevel = TrustLevel.SEMI_TRUSTED
    require_approval: bool = True
    require_pinned_revision: bool = True
    reject_deprecated: bool = True
    require_license: bool = False
    allowed_suppliers: frozenset[str] | None = None
    digest_required_for: frozenset[ArtifactKind] = Field(
        default_factory=_digest_required_by_default
    )


class ArtifactVerificationFinding(BaseModel):
    """Content-free explanation of an artifact verification failure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ArtifactVerificationCode
    severity: Severity
    message: str


class ArtifactVerificationResult(BaseModel):
    """Final allow, warn, or block decision for one artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: str
    manifest_id: str
    action: GuardAction
    findings: tuple[ArtifactVerificationFinding, ...] = ()

    @property
    def is_verified(self) -> bool:
        return self.action == GuardAction.ALLOW

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK


def canonical_manifest_dict(manifest: ArtifactManifest) -> dict[str, Any]:
    """Return the JSON-compatible manifest representation used for BOM export."""
    return manifest.model_dump(mode="json")
