"""Typed contracts for evidence-bound, authority-signed source citations."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity
from trustrail.models.grounding import EvidenceRelationKind, ImpactDomain

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_REFERENCE_PATTERN = r"^sha256:[0-9a-f]{64}$"
_KEY_ID_PATTERN = r"^sha256:[0-9a-f]{64}$"
_SIGNATURE_PATTERN = r"^[0-9a-f]{128}$"


def canonical_citation_json(value: Any) -> str:
    """Serialize citation metadata using a deterministic JSON profile."""
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def citation_digest(value: str | bytes) -> str:
    """Return a domain-separated SHA-256 digest for citation evidence."""
    encoded = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(b"trustrail:citation-integrity:v1\x00" + encoded).hexdigest()


def citation_reference(value: str | bytes) -> str:
    """Return a content-free reference suitable for findings and audit logs."""
    return f"sha256:{citation_digest(value)}"


def _metadata_digest(value: Any) -> str:
    return citation_digest(canonical_citation_json(value))


def _aware(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


class SourceAvailability(StrEnum):
    """Current access state of a captured source snapshot."""

    AVAILABLE = "available"
    INACCESSIBLE = "inaccessible"


class CitationIntegrityCode(StrEnum):
    """Stable, content-free citation verification outcomes."""

    VERIFIED = "verified"
    LIMIT_EXCEEDED = "limit_exceeded"
    DUPLICATE_IDENTITY = "duplicate_identity"
    SOURCE_INTEGRITY_INVALID = "source_integrity_invalid"
    CHUNK_INTEGRITY_INVALID = "chunk_integrity_invalid"
    RETRIEVAL_INTEGRITY_INVALID = "retrieval_integrity_invalid"
    TRANSFORMATION_INTEGRITY_INVALID = "transformation_integrity_invalid"
    CLAIM_INTEGRITY_INVALID = "claim_integrity_invalid"
    UNKNOWN_SIGNING_KEY = "unknown_signing_key"
    CITATION_SIGNATURE_INVALID = "citation_signature_invalid"
    RESPONSE_BINDING_MISMATCH = "response_binding_mismatch"
    CLAIM_BINDING_MISMATCH = "claim_binding_mismatch"
    SOURCE_BINDING_MISMATCH = "source_binding_mismatch"
    CHUNK_BINDING_MISMATCH = "chunk_binding_mismatch"
    RETRIEVAL_BINDING_MISMATCH = "retrieval_binding_mismatch"
    TRANSFORMATION_BINDING_MISMATCH = "transformation_binding_mismatch"
    CHUNK_NOT_RETRIEVED = "chunk_not_retrieved"
    UNTRUSTED_ASSESSOR = "untrusted_assessor"
    ASSESSMENT_BINDING_MISMATCH = "assessment_binding_mismatch"
    ATTRIBUTION_MISSING = "attribution_missing"
    UNSUPPORTED_CLAIM = "unsupported_claim"
    CONTRADICTED_CLAIM = "contradicted_claim"
    STALE_EVIDENCE = "stale_evidence"
    INACCESSIBLE_EVIDENCE = "inaccessible_evidence"


class CitationSource(BaseModel):
    """One immutable source snapshot captured outside model control."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    source_uri: str = Field(min_length=1, max_length=2_048)
    snapshot: str = Field(min_length=1, max_length=10_000_000, exclude=True, repr=False)
    snapshot_sha256: str = Field(pattern=_DIGEST_PATTERN)
    captured_at: datetime
    availability: SourceAvailability = SourceAvailability.AVAILABLE

    @field_validator("captured_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _aware(value, field_name="captured_at")

    @classmethod
    def from_content(
        cls,
        *,
        source_id: str,
        source_uri: str,
        snapshot: str,
        captured_at: datetime | None = None,
        availability: SourceAvailability = SourceAvailability.AVAILABLE,
    ) -> CitationSource:
        """Capture a source and bind its stable identity to exact content."""
        return cls(
            source_id=source_id,
            source_uri=source_uri,
            snapshot=snapshot,
            snapshot_sha256=citation_digest(snapshot),
            captured_at=captured_at or datetime.now(tz=UTC),
            availability=availability,
        )

    @property
    def has_valid_integrity(self) -> bool:
        return self.snapshot_sha256 == citation_digest(self.snapshot)

    @model_validator(mode="after")
    def validate_integrity(self) -> CitationSource:
        if not self.has_valid_integrity:
            raise ValueError("citation source snapshot integrity check failed")
        return self


class CitationChunk(BaseModel):
    """Exact retrieved chunk linked to one immutable source snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    chunk_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    source_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    source_snapshot_sha256: str = Field(pattern=_DIGEST_PATTERN)
    content: str = Field(min_length=1, max_length=1_000_000, exclude=True, repr=False)
    content_sha256: str = Field(pattern=_DIGEST_PATTERN)
    ordinal: int = Field(ge=0, le=10_000_000)

    @classmethod
    def from_content(
        cls,
        *,
        chunk_id: str,
        source: CitationSource,
        content: str,
        ordinal: int,
    ) -> CitationChunk:
        """Create a chunk bound to the exact captured source snapshot."""
        return cls(
            chunk_id=chunk_id,
            source_id=source.source_id,
            source_snapshot_sha256=source.snapshot_sha256,
            content=content,
            content_sha256=citation_digest(content),
            ordinal=ordinal,
        )

    @property
    def has_valid_integrity(self) -> bool:
        return self.content_sha256 == citation_digest(self.content)

    @model_validator(mode="after")
    def validate_integrity(self) -> CitationChunk:
        if not self.has_valid_integrity:
            raise ValueError("citation chunk integrity check failed")
        return self


class CitationRetrieval(BaseModel):
    """Authorized retrieval event containing exact chunk identities."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    retrieval_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    query_reference: str = Field(pattern=_REFERENCE_PATTERN)
    authorization_reference: str = Field(pattern=_REFERENCE_PATTERN)
    retrieved_at: datetime
    chunk_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    retrieval_sha256: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("retrieved_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        return _aware(value, field_name="retrieved_at")

    @classmethod
    def from_metadata(
        cls,
        *,
        retrieval_id: str,
        query: str,
        authorization_context: str,
        chunk_ids: tuple[str, ...],
        retrieved_at: datetime | None = None,
    ) -> CitationRetrieval:
        """Capture authorized retrieval metadata without retaining query or identity text."""
        timestamp = retrieved_at or datetime.now(tz=UTC)
        values: dict[str, Any] = {
            "retrieval_id": retrieval_id,
            "query_reference": citation_reference(query),
            "authorization_reference": citation_reference(authorization_context),
            "retrieved_at": timestamp,
            "chunk_ids": chunk_ids,
        }
        return cls(
            retrieval_id=retrieval_id,
            query_reference=citation_reference(query),
            authorization_reference=citation_reference(authorization_context),
            retrieved_at=timestamp,
            chunk_ids=chunk_ids,
            retrieval_sha256=cls.digest_values(values),
        )

    @staticmethod
    def digest_values(values: dict[str, Any]) -> str:
        payload = dict(values)
        retrieved_at = payload.get("retrieved_at")
        if isinstance(retrieved_at, datetime):
            payload["retrieved_at"] = retrieved_at.isoformat()
        payload["chunk_ids"] = list(payload.get("chunk_ids", ()))
        return _metadata_digest(payload)

    @property
    def has_valid_integrity(self) -> bool:
        return self.retrieval_sha256 == self.digest_values(
            self.model_dump(exclude={"retrieval_sha256"})
        )

    @model_validator(mode="after")
    def validate_retrieval(self) -> CitationRetrieval:
        if len(self.chunk_ids) != len(set(self.chunk_ids)):
            raise ValueError("citation retrieval contains duplicate chunk IDs")
        if not self.has_valid_integrity:
            raise ValueError("citation retrieval integrity check failed")
        return self


class CitationTransformation(BaseModel):
    """Content-digest lineage for a transformation of one retrieved chunk."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    transformation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    input_chunk_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    input_sha256: str = Field(pattern=_DIGEST_PATTERN)
    operation: str = Field(pattern=_IDENTIFIER_PATTERN)
    transformer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    output: str = Field(min_length=1, max_length=1_000_000, exclude=True, repr=False)
    output_sha256: str = Field(pattern=_DIGEST_PATTERN)

    @classmethod
    def from_content(
        cls,
        *,
        transformation_id: str,
        chunk: CitationChunk,
        operation: str,
        transformer_id: str,
        output: str,
    ) -> CitationTransformation:
        """Record a content transformation without losing input lineage."""
        return cls(
            transformation_id=transformation_id,
            input_chunk_id=chunk.chunk_id,
            input_sha256=chunk.content_sha256,
            operation=operation,
            transformer_id=transformer_id,
            output=output,
            output_sha256=citation_digest(output),
        )

    @property
    def evidence_sha256(self) -> str:
        """Return a digest of the complete transformation lineage record."""
        return _metadata_digest(self.model_dump(mode="json", exclude={"output"}))

    @property
    def has_valid_integrity(self) -> bool:
        return self.output_sha256 == citation_digest(self.output)

    @model_validator(mode="after")
    def validate_integrity(self) -> CitationTransformation:
        if not self.has_valid_integrity:
            raise ValueError("citation transformation integrity check failed")
        return self


class CitationClaim(BaseModel):
    """Material response claim with a content digest and impact classification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    text: str = Field(min_length=1, max_length=100_000, exclude=True, repr=False)
    text_sha256: str = Field(pattern=_DIGEST_PATTERN)
    impact_domain: ImpactDomain = ImpactDomain.GENERAL

    @classmethod
    def from_text(
        cls,
        *,
        claim_id: str,
        text: str,
        impact_domain: ImpactDomain = ImpactDomain.GENERAL,
    ) -> CitationClaim:
        """Create a claim bound to its exact response text."""
        return cls(
            claim_id=claim_id,
            text=text,
            text_sha256=citation_digest(text),
            impact_domain=impact_domain,
        )

    @property
    def has_valid_integrity(self) -> bool:
        return self.text_sha256 == citation_digest(self.text)

    @model_validator(mode="after")
    def validate_integrity(self) -> CitationClaim:
        if not self.has_valid_integrity:
            raise ValueError("citation claim integrity check failed")
        return self


class ClaimEvidenceAssessment(BaseModel):
    """Provider-neutral semantic assessment of a claim against one exact chunk."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    chunk_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    claim_sha256: str = Field(pattern=_DIGEST_PATTERN)
    chunk_sha256: str = Field(pattern=_DIGEST_PATTERN)
    relation: EvidenceRelationKind
    confidence: float = Field(ge=0.0, le=1.0)
    assessor_id: str = Field(pattern=_IDENTIFIER_PATTERN)


class CitationTrustedKey(BaseModel):
    """Out-of-band public key for an authorized citation issuer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    public_key: bytes = Field(min_length=32, max_length=32, exclude=True, repr=False)
    revoked: bool = False

    @property
    def key_id(self) -> str:
        return citation_reference(self.public_key)


class VerifiedCitation(BaseModel):
    """Authority-signed attribution bound to response, claim, retrieval, and source."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    format_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    citation_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    issuer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    key_id: str = Field(pattern=_KEY_ID_PATTERN)
    response_sha256: str = Field(pattern=_DIGEST_PATTERN)
    claim_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    claim_sha256: str = Field(pattern=_DIGEST_PATTERN)
    source_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    source_uri: str = Field(min_length=1, max_length=2_048)
    source_snapshot_sha256: str = Field(pattern=_DIGEST_PATTERN)
    chunk_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    chunk_sha256: str = Field(pattern=_DIGEST_PATTERN)
    retrieval_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    retrieval_sha256: str = Field(pattern=_DIGEST_PATTERN)
    transformation_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    transformation_sha256: str | None = Field(default=None, pattern=_DIGEST_PATTERN)
    signature: str | None = Field(default=None, pattern=_SIGNATURE_PATTERN)

    @model_validator(mode="after")
    def validate_transformation_binding(self) -> VerifiedCitation:
        if (self.transformation_id is None) != (self.transformation_sha256 is None):
            raise ValueError("citation transformation ID and digest must be provided together")
        return self

    @property
    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})

    @property
    def signing_bytes(self) -> bytes:
        return canonical_citation_json(self.signing_payload).encode("utf-8")


class CitationEvidenceBundle(BaseModel):
    """Complete response attribution package evaluated at the release boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    response: str = Field(min_length=1, max_length=1_000_000, exclude=True, repr=False)
    claims: tuple[CitationClaim, ...] = Field(min_length=1, max_length=10_000)
    sources: tuple[CitationSource, ...] = Field(min_length=1, max_length=10_000)
    chunks: tuple[CitationChunk, ...] = Field(min_length=1, max_length=10_000)
    retrievals: tuple[CitationRetrieval, ...] = Field(min_length=1, max_length=10_000)
    transformations: tuple[CitationTransformation, ...] = Field(default=(), max_length=10_000)
    assessments: tuple[ClaimEvidenceAssessment, ...] = Field(min_length=1, max_length=20_000)
    citations: tuple[VerifiedCitation, ...] = Field(default=(), max_length=20_000)

    @model_validator(mode="after")
    def require_unique_identities(self) -> CitationEvidenceBundle:
        groups = (
            ("claim", [item.claim_id for item in self.claims]),
            ("source", [item.source_id for item in self.sources]),
            ("chunk", [item.chunk_id for item in self.chunks]),
            ("retrieval", [item.retrieval_id for item in self.retrievals]),
            ("transformation", [item.transformation_id for item in self.transformations]),
            ("citation", [item.citation_id for item in self.citations]),
        )
        for label, identities in groups:
            if len(identities) != len(set(identities)):
                raise ValueError(f"citation evidence contains duplicate {label} IDs")
        return self


def _high_impact_domains() -> frozenset[ImpactDomain]:
    return frozenset(domain for domain in ImpactDomain if domain != ImpactDomain.GENERAL)


class CitationIntegrityPolicy(BaseModel):
    """Thresholds and fail behavior for evidence-backed citations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trusted_assessor_ids: frozenset[str] = Field(min_length=1)
    minimum_support_confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    contradiction_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    max_evidence_age_seconds: int = Field(default=2_592_000, ge=1, le=31_536_000)
    require_accessible_sources: bool = True
    high_impact_domains: frozenset[ImpactDomain] = Field(default_factory=_high_impact_domains)
    general_insufficient_action: Literal[GuardAction.WARN, GuardAction.BLOCK] = GuardAction.WARN
    high_impact_insufficient_action: Literal[GuardAction.WARN, GuardAction.BLOCK] = (
        GuardAction.BLOCK
    )
    max_response_chars: int = Field(default=100_000, ge=1, le=1_000_000)
    max_claims: int = Field(default=100, ge=1, le=10_000)
    max_citations: int = Field(default=200, ge=1, le=20_000)


class CitationIntegrityFinding(BaseModel):
    """Content-free explanation of one citation verification failure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: CitationIntegrityCode
    severity: Severity
    message: str = Field(min_length=1, max_length=500)
    claim_reference: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)
    citation_reference: str | None = Field(default=None, pattern=_REFERENCE_PATTERN)


class CitationIntegritySignal(BaseModel):
    """Content-free claim support summary for policy and observability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_reference: str = Field(pattern=_REFERENCE_PATTERN)
    impact_domain: ImpactDomain
    support_confidence: float = Field(ge=0.0, le=1.0)
    contradiction_confidence: float = Field(ge=0.0, le=1.0)
    cited_chunk_count: int = Field(ge=0)
    evidence_stale: bool
    evidence_accessible: bool


class CitationIntegrityResult(BaseModel):
    """Decision and redacted diagnostics from citation verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: Literal[GuardAction.ALLOW, GuardAction.WARN, GuardAction.BLOCK]
    findings: tuple[CitationIntegrityFinding, ...] = ()
    signals: tuple[CitationIntegritySignal, ...] = ()
    approved_citations: tuple[VerifiedCitation, ...] = ()

    @property
    def is_releasable(self) -> bool:
        return self.action in {GuardAction.ALLOW, GuardAction.WARN}


class CitationRelease(BaseModel):
    """Response plus only the citations authorized for display."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    response: str = Field(exclude=True, repr=False)
    action: Literal[GuardAction.ALLOW, GuardAction.WARN]
    citations: tuple[VerifiedCitation, ...]
    signals: tuple[CitationIntegritySignal, ...]
