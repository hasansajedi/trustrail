"""Integration coverage for evidence verification before output consumption."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from trustrail import (
    ClaimKind,
    EvidenceGroundingVerifier,
    EvidenceRelation,
    EvidenceRelationKind,
    GroundingCitation,
    GroundingClaim,
    GroundingEvidence,
    GroundingPolicy,
    GroundingRequest,
    GroundingVerificationError,
    HumanReviewDecision,
    HumanReviewGrant,
    ImpactDomain,
    TrustLevel,
)

NOW = datetime(2026, 8, 26, 12, tzinfo=UTC)
OUTPUT = "The documented refund window is thirty days."


def _request(*, high_impact: bool = False) -> GroundingRequest:
    source_count = 2 if high_impact else 1
    evidence = tuple(
        GroundingEvidence.from_content(
            evidence_id=f"evidence-{index}",
            source_id=f"independent-source-{index}",
            source_uri=f"https://knowledge.example.test/refunds/{index}",
            content=f"Reviewed source {index}: {OUTPUT}",
            trust_level=TrustLevel.TRUSTED,
            retrieved_at=NOW,
        )
        for index in range(1, source_count + 1)
    )
    citations = tuple(
        GroundingCitation.from_evidence(citation_id=f"citation-{index}", evidence=item)
        for index, item in enumerate(evidence, start=1)
    )
    claim = GroundingClaim(
        claim_id="claim-1",
        text=OUTPUT,
        kind=ClaimKind.RECOMMENDATION if high_impact else ClaimKind.FACT,
        impact_domain=ImpactDomain.FINANCIAL if high_impact else ImpactDomain.GENERAL,
        model_confidence=0.92,
        citation_ids=frozenset(citation.citation_id for citation in citations),
    )
    return GroundingRequest(
        request_id="response-1",
        output=OUTPUT,
        claims=(claim,),
        evidence=evidence,
        relations=tuple(
            EvidenceRelation(
                claim_id=claim.claim_id,
                evidence_id=item.evidence_id,
                relation=EvidenceRelationKind.SUPPORTS,
                confidence=0.94,
                assessor_id="grounding-service",
            )
            for item in evidence
        ),
        citations=citations,
    )


def _verifier() -> EvidenceGroundingVerifier:
    return EvidenceGroundingVerifier(
        GroundingPolicy(
            trusted_assessor_ids=frozenset({"grounding-service"}),
            trusted_reviewer_ids=frozenset({"risk-reviewer"}),
        )
    )


def test_verified_general_output_can_cross_the_application_boundary():
    assert _verifier().require(_request(), now=NOW) == OUTPUT


def test_high_impact_output_stays_closed_until_bound_human_approval():
    request = _request(high_impact=True)
    verifier = _verifier()

    with pytest.raises(GroundingVerificationError) as exc_info:
        verifier.require(request, now=NOW)
    assert exc_info.value.result.requires_review

    approved = request.model_copy(
        update={
            "human_review": HumanReviewGrant(
                review_id="review-1",
                request_id=request.request_id,
                reviewer_id="risk-reviewer",
                claim_ids=frozenset({"claim-1"}),
                assessment_sha256=request.assessment_sha256,
                decision=HumanReviewDecision.APPROVED,
                issued_at=NOW - timedelta(minutes=1),
                expires_at=NOW + timedelta(minutes=10),
            )
        }
    )

    assert verifier.require(approved, now=NOW) == OUTPUT
