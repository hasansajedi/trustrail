"""Verify evidence, citations, and uncertainty before releasing model output."""

from datetime import UTC, datetime

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
    TrustLevel,
)

output = "The approved refund period is thirty days."
evidence = GroundingEvidence.from_content(
    evidence_id="evidence-1",
    source_id="reviewed-handbook",
    source_uri="https://docs.example.test/refunds",
    content="The standard refund period is thirty days.",
    trust_level=TrustLevel.TRUSTED,
    retrieved_at=datetime.now(tz=UTC),
)
citation = GroundingCitation.from_evidence(citation_id="refund-policy", evidence=evidence)
claim = GroundingClaim(
    claim_id="claim-1",
    text=output,
    kind=ClaimKind.FACT,
    model_confidence=0.94,
    citation_ids=frozenset({citation.citation_id}),
)
request = GroundingRequest(
    request_id="response-42",
    output=output,
    claims=(claim,),
    evidence=(evidence,),
    relations=(
        EvidenceRelation(
            claim_id=claim.claim_id,
            evidence_id=evidence.evidence_id,
            relation=EvidenceRelationKind.SUPPORTS,
            confidence=0.96,
            assessor_id="fact-checker-v3",
        ),
    ),
    citations=(citation,),
)
verifier = EvidenceGroundingVerifier(
    GroundingPolicy(
        trusted_assessor_ids=frozenset({"fact-checker-v3"}),
        trusted_reviewer_ids=frozenset({"risk-reviewer"}),
    )
)

print(verifier.require(request))
