"""Issue authority-signed citations from retrieval metadata and verify support."""

from datetime import UTC, datetime

from trustrail import (
    CitationChunk,
    CitationClaim,
    CitationEvidenceBundle,
    CitationIntegrityPolicy,
    CitationIntegrityVerifier,
    CitationIssuer,
    CitationRetrieval,
    CitationSource,
    ClaimEvidenceAssessment,
    EvidenceRelationKind,
)

now = datetime.now(tz=UTC)
response = "The approved refund window is thirty days."
source = CitationSource.from_content(
    source_id="refund-handbook",
    source_uri="https://docs.example.test/refunds",
    snapshot=f"Customer policy. {response} Contact support for exceptions.",
    captured_at=now,
)
chunk = CitationChunk.from_content(
    chunk_id="refund-handbook:7",
    source=source,
    content=response,
    ordinal=7,
)
retrieval = CitationRetrieval.from_metadata(
    retrieval_id="search-42",
    query="What is the approved refund window?",
    authorization_context="tenant:acme:user:7",
    chunk_ids=(chunk.chunk_id,),
    retrieved_at=now,
)
claim = CitationClaim.from_text(claim_id="claim-1", text=response)

# Keep this issuer in the trusted retrieval service, outside the model process.
issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")
citation = issuer.issue(
    citation_id="source-1",
    response=response,
    claim=claim,
    source=source,
    chunk=chunk,
    retrieval=retrieval,
)

# This assessment can come from any provider that implements your evaluation
# workflow. The verifier trusts its configured identity, not provider-specific data.
assessment = ClaimEvidenceAssessment(
    claim_id=claim.claim_id,
    chunk_id=chunk.chunk_id,
    claim_sha256=claim.text_sha256,
    chunk_sha256=chunk.content_sha256,
    relation=EvidenceRelationKind.SUPPORTS,
    confidence=0.97,
    assessor_id="entailment-service-v3",
)
bundle = CitationEvidenceBundle(
    response=response,
    claims=(claim,),
    sources=(source,),
    chunks=(chunk,),
    retrievals=(retrieval,),
    assessments=(assessment,),
    citations=(citation,),
)
verifier = CitationIntegrityVerifier(
    (issuer.trusted_key,),
    CitationIntegrityPolicy(
        trusted_assessor_ids=frozenset({assessment.assessor_id}),
    ),
)

release = verifier.release(bundle, now=now)
print(release.action)
print(release.response)
print(release.citations[0].source_uri)
