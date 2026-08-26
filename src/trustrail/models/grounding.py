"""Typed evidence, citation, confidence, and review models for OWASP LLM09."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from trustrail.models.enums import GuardAction, Severity, TrustLevel


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class ImpactDomain(StrEnum):
    """Decision domains used to mandate independent human review."""

    GENERAL = "general"
    MEDICAL = "medical"
    LEGAL = "legal"
    FINANCIAL = "financial"
    SECURITY = "security"
    SAFETY = "safety"
    EMPLOYMENT = "employment"
    OTHER_HIGH_IMPACT = "other_high_impact"


class ClaimKind(StrEnum):
    """Type of assertion made by the model output."""

    FACT = "fact"
    RECOMMENDATION = "recommendation"
    PREDICTION = "prediction"
    CODE_OR_CONFIGURATION = "code_or_configuration"


class EvidenceRelationKind(StrEnum):
    """Externally assessed relationship between evidence and a claim."""

    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    IRRELEVANT = "irrelevant"


class HumanReviewDecision(StrEnum):
    """Independent reviewer decision for bound high-impact claims."""

    APPROVED = "approved"
    REJECTED = "rejected"


class GroundingSupportStatus(StrEnum):
    """Downstream-facing summary of evidence support."""

    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    CONTRADICTED = "contradicted"


class GroundingVerificationCode(StrEnum):
    """Stable machine-readable grounding and overreliance outcomes."""

    OUTPUT_TOO_LARGE = "output_too_large"
    CLAIM_LIMIT_EXCEEDED = "claim_limit_exceeded"
    EVIDENCE_LIMIT_EXCEEDED = "evidence_limit_exceeded"
    CLAIM_NOT_IN_OUTPUT = "claim_not_in_output"
    BROKEN_EVIDENCE_INTEGRITY = "broken_evidence_integrity"
    EVIDENCE_FROM_FUTURE = "evidence_from_future"
    EVIDENCE_STALE = "evidence_stale"
    EVIDENCE_TRUST_TOO_LOW = "evidence_trust_too_low"
    UNKNOWN_CLAIM = "unknown_claim"
    UNKNOWN_EVIDENCE = "unknown_evidence"
    UNTRUSTED_ASSESSOR = "untrusted_assessor"
    UNKNOWN_CITATION = "unknown_citation"
    CITATION_MISMATCH = "citation_mismatch"
    UNVERIFIED_CITATION = "unverified_citation"
    UNSUPPORTED_CLAIM = "unsupported_claim"
    ABSOLUTE_CLAIM_UNASSESSED = "absolute_claim_unassessed"
    ABSOLUTE_CLAIM_UNSUPPORTED = "absolute_claim_unsupported"
    CONTRADICTED_CLAIM = "contradicted_claim"
    UNCERTAINTY_NOT_DISCLOSED = "uncertainty_not_disclosed"
    HIGH_IMPACT_DOMAIN_UNCLASSIFIED = "high_impact_domain_unclassified"
    HIGH_IMPACT_EVIDENCE_INSUFFICIENT = "high_impact_evidence_insufficient"
    HUMAN_REVIEW_REQUIRED = "human_review_required"
    HUMAN_REVIEW_INVALID = "human_review_invalid"
    HUMAN_REVIEW_REJECTED = "human_review_rejected"


class GroundingEvidence(BaseModel):
    """Verified source content and provenance available to support claims."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str = Field(min_length=1, max_length=256)
    source_id: str = Field(min_length=1, max_length=256)
    source_uri: str = Field(min_length=1, max_length=2_048)
    content: str = Field(min_length=1, max_length=1_000_000, exclude=True, repr=False)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trust_level: TrustLevel
    retrieved_at: datetime

    @field_validator("retrieved_at")
    @classmethod
    def require_aware_retrieval_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("retrieved_at must be timezone-aware")
        return value

    @classmethod
    def from_content(
        cls,
        *,
        evidence_id: str,
        source_id: str,
        source_uri: str,
        content: str,
        trust_level: TrustLevel,
        retrieved_at: datetime | None = None,
    ) -> GroundingEvidence:
        """Create evidence with a digest of the exact validated source text."""
        return cls(
            evidence_id=evidence_id,
            source_id=source_id,
            source_uri=source_uri,
            content=content,
            content_sha256=_sha256_text(content),
            trust_level=trust_level,
            retrieved_at=retrieved_at or datetime.now(tz=UTC),
        )

    @model_validator(mode="after")
    def validate_integrity(self) -> GroundingEvidence:
        if not self.has_valid_integrity:
            raise ValueError("grounding evidence integrity check failed")
        return self

    @property
    def has_valid_integrity(self) -> bool:
        """Return whether evidence still matches its captured digest."""
        return self.content_sha256 == _sha256_text(self.content)


class GroundingCitation(BaseModel):
    """Citation emitted with the output and bound to exact evidence provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    citation_id: str = Field(min_length=1, max_length=256)
    evidence_id: str = Field(min_length=1, max_length=256)
    source_uri: str = Field(min_length=1, max_length=2_048)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def from_evidence(
        cls,
        *,
        citation_id: str,
        evidence: GroundingEvidence,
    ) -> GroundingCitation:
        """Create a citation pinned to evidence identity, location, and bytes."""
        return cls(
            citation_id=citation_id,
            evidence_id=evidence.evidence_id,
            source_uri=evidence.source_uri,
            evidence_sha256=evidence.content_sha256,
        )


class GroundingClaim(BaseModel):
    """One output claim with model confidence and user-facing uncertainty state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: str = Field(min_length=1, max_length=256)
    text: str = Field(min_length=1, max_length=100_000, exclude=True, repr=False)
    kind: ClaimKind
    impact_domain: ImpactDomain = ImpactDomain.GENERAL
    model_confidence: float = Field(ge=0.0, le=1.0)
    uncertainty_disclosed: bool = False
    citation_ids: frozenset[str] = Field(default_factory=frozenset)


class EvidenceRelation(BaseModel):
    """Trusted verifier signal connecting one claim to one evidence item."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: str = Field(min_length=1, max_length=256)
    evidence_id: str = Field(min_length=1, max_length=256)
    relation: EvidenceRelationKind
    confidence: float = Field(ge=0.0, le=1.0)
    assessor_id: str = Field(min_length=1, max_length=256)


class HumanReviewGrant(BaseModel):
    """Time-bound human decision tied to exact claims and evidence assessment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    review_id: str = Field(min_length=1, max_length=256)
    request_id: str = Field(min_length=1, max_length=256)
    reviewer_id: str = Field(min_length=1, max_length=256)
    claim_ids: frozenset[str] = Field(min_length=1)
    assessment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: HumanReviewDecision
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_review_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("human review timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_window(self) -> HumanReviewGrant:
        if self.expires_at <= self.issued_at:
            raise ValueError("human review expiration must follow issuance")
        return self


class GroundingRequest(BaseModel):
    """Complete evidence package for model output verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str = Field(min_length=1, max_length=256)
    output: str = Field(min_length=1, max_length=1_000_000, exclude=True, repr=False)
    claims: tuple[GroundingClaim, ...] = Field(min_length=1)
    evidence: tuple[GroundingEvidence, ...] = Field(min_length=1)
    relations: tuple[EvidenceRelation, ...] = Field(min_length=1)
    citations: tuple[GroundingCitation, ...] = ()
    human_review: HumanReviewGrant | None = None

    @model_validator(mode="after")
    def validate_unique_ids(self) -> GroundingRequest:
        for label, identifiers in (
            ("claim", [claim.claim_id for claim in self.claims]),
            ("evidence", [item.evidence_id for item in self.evidence]),
            ("citation", [citation.citation_id for citation in self.citations]),
        ):
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"grounding request contains duplicate {label} IDs")
        return self

    @property
    def assessment_sha256(self) -> str:
        """Bind review to exact claims, evidence digests, citations, and relations."""
        return _canonical_digest(
            {
                "citations": [citation.model_dump(mode="json") for citation in self.citations],
                "claims": [
                    {
                        **claim.model_dump(mode="json"),
                        "text_sha256": _sha256_text(claim.text),
                    }
                    for claim in self.claims
                ],
                "evidence": [
                    {
                        "content_sha256": item.content_sha256,
                        "evidence_id": item.evidence_id,
                        "source_id": item.source_id,
                        "source_uri": item.source_uri,
                        "retrieved_at": item.retrieved_at.isoformat(),
                        "trust_level": item.trust_level.value,
                    }
                    for item in self.evidence
                ],
                "relations": [relation.model_dump(mode="json") for relation in self.relations],
                "request_id": self.request_id,
            }
        )


def _high_impact_domains() -> frozenset[ImpactDomain]:
    return frozenset(
        {
            ImpactDomain.MEDICAL,
            ImpactDomain.LEGAL,
            ImpactDomain.FINANCIAL,
            ImpactDomain.SECURITY,
            ImpactDomain.SAFETY,
            ImpactDomain.EMPLOYMENT,
            ImpactDomain.OTHER_HIGH_IMPACT,
        }
    )


class GroundingPolicy(BaseModel):
    """Fail-closed evidence and review requirements for generated claims."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    trusted_assessor_ids: frozenset[str] = Field(min_length=1)
    trusted_reviewer_ids: frozenset[str] = Field(min_length=1)
    minimum_evidence_trust: TrustLevel = TrustLevel.SEMI_TRUSTED
    max_evidence_age_seconds: int = Field(default=2_592_000, ge=1, le=31_536_000)
    minimum_support_confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    contradiction_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    uncertainty_disclosure_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    high_impact_domains: frozenset[ImpactDomain] = Field(default_factory=_high_impact_domains)
    minimum_high_impact_sources: int = Field(default=2, ge=1, le=20)
    require_citations: bool = True
    max_output_chars: int = Field(default=100_000, ge=1, le=1_000_000)
    max_claims: int = Field(default=100, ge=1, le=10_000)
    max_evidence_items: int = Field(default=200, ge=1, le=10_000)

    @model_validator(mode="after")
    def require_independent_reviewers(self) -> GroundingPolicy:
        if self.trusted_assessor_ids.intersection(self.trusted_reviewer_ids):
            raise ValueError("grounding assessors and human reviewers must be independent")
        return self


class GroundingFinding(BaseModel):
    """Content-free explanation for a grounding or review decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: GroundingVerificationCode
    severity: Severity
    message: str
    claim_id: str | None = None


class GroundingSignal(BaseModel):
    """Provenance and confidence signal safe for downstream policy evaluation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: str
    impact_domain: ImpactDomain
    support_status: GroundingSupportStatus
    model_confidence: float
    support_confidence: float
    contradiction_confidence: float
    evidence_ids: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()
    citation_ids: tuple[str, ...] = ()
    uncertainty_disclosed: bool
    human_reviewed: bool


class GroundingResult(BaseModel):
    """Decision plus content-free provenance and confidence signals."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    action: Literal[GuardAction.ALLOW, GuardAction.BLOCK, GuardAction.REQUIRE_APPROVAL]
    findings: tuple[GroundingFinding, ...] = ()
    signals: tuple[GroundingSignal, ...] = ()
    approved_output: str | None = Field(default=None, exclude=True, repr=False)

    @property
    def is_allowed(self) -> bool:
        return self.action == GuardAction.ALLOW

    @property
    def is_blocked(self) -> bool:
        return self.action == GuardAction.BLOCK

    @property
    def requires_review(self) -> bool:
        return self.action == GuardAction.REQUIRE_APPROVAL
