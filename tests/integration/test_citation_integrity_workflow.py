"""Integration coverage for signed citations at a RAG response boundary."""

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
    GuardAction,
)


def test_application_can_release_only_metadata_derived_supported_citations():
    now = datetime(2026, 9, 12, 12, tzinfo=UTC)
    response = "Support is available every weekday."
    source = CitationSource.from_content(
        source_id="support-handbook",
        source_uri="https://docs.example.test/support",
        snapshot="Customer handbook: Support is available every weekday.",
        captured_at=now,
    )
    chunk = CitationChunk.from_content(
        chunk_id="support-handbook:12",
        source=source,
        content=response,
        ordinal=12,
    )
    retrieval = CitationRetrieval.from_metadata(
        retrieval_id="search-42",
        query="When is support available?",
        authorization_context="tenant:acme:principal:user-7",
        chunk_ids=(chunk.chunk_id,),
        retrieved_at=now,
    )
    claim = CitationClaim.from_text(claim_id="claim-1", text=response)
    issuer = CitationIssuer.generate(issuer_id="trusted-retrieval-gateway")
    citation = issuer.issue(
        citation_id="source-1",
        response=response,
        claim=claim,
        source=source,
        chunk=chunk,
        retrieval=retrieval,
    )
    bundle = CitationEvidenceBundle(
        response=response,
        claims=(claim,),
        sources=(source,),
        chunks=(chunk,),
        retrievals=(retrieval,),
        assessments=(
            ClaimEvidenceAssessment(
                claim_id=claim.claim_id,
                chunk_id=chunk.chunk_id,
                claim_sha256=claim.text_sha256,
                chunk_sha256=chunk.content_sha256,
                relation=EvidenceRelationKind.SUPPORTS,
                confidence=0.97,
                assessor_id="entailment-service",
            ),
        ),
        citations=(citation,),
    )
    verifier = CitationIntegrityVerifier(
        (issuer.trusted_key,),
        CitationIntegrityPolicy(
            trusted_assessor_ids=frozenset({"entailment-service"}),
        ),
    )

    release = verifier.release(bundle, now=now)

    assert release.action == GuardAction.ALLOW
    assert release.response == response
    assert release.citations[0].source_uri == source.source_uri
    assert release.citations[0].chunk_sha256 == chunk.content_sha256
