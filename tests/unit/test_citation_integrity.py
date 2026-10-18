"""Unit tests for OWASP AISVS C7 citation-integrity controls."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from trustrail import (
    CitationChunk,
    CitationClaim,
    CitationEvidenceBundle,
    CitationIntegrityCode,
    CitationIntegrityError,
    CitationIntegrityPolicy,
    CitationIntegrityVerifier,
    CitationIssuer,
    CitationRetrieval,
    CitationSource,
    CitationTransformation,
    ClaimEvidenceAssessment,
    EvidenceRelationKind,
    GuardAction,
    ImpactDomain,
    SourceAvailability,
    citation_digest,
)

NOW = datetime(2026, 9, 12, 12, tzinfo=UTC)
RESPONSE = "The approved refund window is thirty days."
SOURCE_TEXT = "Policy handbook. The approved refund window is thirty days. Contact support."
CHUNK_TEXT = "The approved refund window is thirty days."


def _components(
    *,
    domain: ImpactDomain = ImpactDomain.GENERAL,
    retrieved_at: datetime = NOW,
    availability: SourceAvailability = SourceAvailability.AVAILABLE,
):
    source = CitationSource.from_content(
        source_id="policy-handbook",
        source_uri="https://docs.example.test/refunds",
        snapshot=SOURCE_TEXT,
        captured_at=NOW,
        availability=availability,
    )
    chunk = CitationChunk.from_content(
        chunk_id="refunds:7",
        source=source,
        content=CHUNK_TEXT,
        ordinal=7,
    )
    retrieval = CitationRetrieval.from_metadata(
        retrieval_id="retrieval-1",
        query="What is the refund window?",
        authorization_context="tenant:acme:user:42",
        chunk_ids=(chunk.chunk_id,),
        retrieved_at=retrieved_at,
    )
    claim = CitationClaim.from_text(
        claim_id="claim-1",
        text=RESPONSE,
        impact_domain=domain,
    )
    transformation = CitationTransformation.from_content(
        transformation_id="transform-1",
        chunk=chunk,
        operation="normalize_whitespace",
        transformer_id="retrieval-pipeline-v2",
        output=CHUNK_TEXT,
    )
    return source, chunk, retrieval, claim, transformation


def _bundle(
    issuer: CitationIssuer,
    *,
    domain: ImpactDomain = ImpactDomain.GENERAL,
    retrieved_at: datetime = NOW,
    availability: SourceAvailability = SourceAvailability.AVAILABLE,
    relation: EvidenceRelationKind = EvidenceRelationKind.SUPPORTS,
    confidence: float = 0.96,
) -> CitationEvidenceBundle:
    source, chunk, retrieval, claim, transformation = _components(
        domain=domain,
        retrieved_at=retrieved_at,
        availability=availability,
    )
    citation = issuer.issue(
        citation_id="citation-1",
        response=RESPONSE,
        claim=claim,
        source=source,
        chunk=chunk,
        retrieval=retrieval,
        transformation=transformation,
    )
    assessment = ClaimEvidenceAssessment(
        claim_id=claim.claim_id,
        chunk_id=chunk.chunk_id,
        claim_sha256=claim.text_sha256,
        chunk_sha256=chunk.content_sha256,
        relation=relation,
        confidence=confidence,
        assessor_id="entailment-service-v3",
    )
    return CitationEvidenceBundle(
        response=RESPONSE,
        claims=(claim,),
        sources=(source,),
        chunks=(chunk,),
        retrievals=(retrieval,),
        transformations=(transformation,),
        assessments=(assessment,),
        citations=(citation,),
    )


def _verifier(issuer: CitationIssuer, **updates: object) -> CitationIntegrityVerifier:
    values: dict[str, object] = {
        "trusted_assessor_ids": frozenset({"entailment-service-v3"}),
    }
    values.update(updates)
    return CitationIntegrityVerifier(
        (issuer.trusted_key,),
        CitationIntegrityPolicy(**values),
    )


def _codes(result: object) -> set[CitationIntegrityCode]:
    return {finding.code for finding in result.findings}  # type: ignore[attr-defined]


def test_issues_and_releases_citation_bound_to_complete_evidence_chain():
    issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")
    bundle = _bundle(issuer)

    release = _verifier(issuer).release(bundle, now=NOW)

    assert release.action == GuardAction.ALLOW
    assert release.response == RESPONSE
    assert release.citations == bundle.citations
    citation = release.citations[0]
    assert citation.response_sha256 == citation_digest(RESPONSE)
    assert citation.source_snapshot_sha256 == bundle.sources[0].snapshot_sha256
    assert citation.chunk_sha256 == bundle.chunks[0].content_sha256
    assert citation.retrieval_sha256 == bundle.retrievals[0].retrieval_sha256
    assert citation.transformation_sha256 == bundle.transformations[0].evidence_sha256


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        (
            "source_uri",
            "https://attacker.test/fake",
            CitationIntegrityCode.CITATION_SIGNATURE_INVALID,
        ),
        ("response_sha256", "0" * 64, CitationIntegrityCode.CITATION_SIGNATURE_INVALID),
        ("chunk_sha256", "0" * 64, CitationIntegrityCode.CITATION_SIGNATURE_INVALID),
    ],
)
def test_rejects_tampered_authority_signed_citation(field: str, value: str, expected):
    issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")
    bundle = _bundle(issuer)
    tampered = bundle.citations[0].model_copy(update={field: value})

    result = _verifier(issuer).verify(
        bundle.model_copy(update={"citations": (tampered,)}),
        now=NOW,
    )

    assert result.action == GuardAction.BLOCK
    assert expected in _codes(result)
    assert not result.approved_citations


def test_rejects_citation_replay_against_changed_response():
    issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")
    bundle = _bundle(issuer)
    changed_response = f"{RESPONSE} This applies worldwide."

    result = _verifier(issuer).verify(
        bundle.model_copy(update={"response": changed_response}),
        now=NOW,
    )

    assert CitationIntegrityCode.RESPONSE_BINDING_MISMATCH in _codes(result)
    assert result.action == GuardAction.BLOCK


def test_rejects_chunk_that_was_not_in_authorized_retrieval():
    issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")
    source, chunk, retrieval, claim, _ = _components()
    other = CitationChunk.from_content(
        chunk_id="other:1",
        source=source,
        content="Policy handbook.",
        ordinal=1,
    )

    with pytest.raises(ValueError, match="absent from the authorized retrieval"):
        issuer.issue(
            citation_id="citation-1",
            response=RESPONSE,
            claim=claim,
            source=source,
            chunk=other,
            retrieval=retrieval,
        )
    assert chunk.chunk_id in retrieval.chunk_ids


def test_rejects_untrusted_or_rebound_claim_support_assessments():
    issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")
    bundle = _bundle(issuer)
    assessment = bundle.assessments[0]

    untrusted = assessment.model_copy(update={"assessor_id": "model-self-assessment"})
    rebound = assessment.model_copy(update={"chunk_sha256": "0" * 64})

    untrusted_result = _verifier(issuer).verify(
        bundle.model_copy(update={"assessments": (untrusted,)}),
        now=NOW,
    )
    rebound_result = _verifier(issuer).verify(
        bundle.model_copy(update={"assessments": (rebound,)}),
        now=NOW,
    )

    assert CitationIntegrityCode.UNTRUSTED_ASSESSOR in _codes(untrusted_result)
    assert CitationIntegrityCode.ASSESSMENT_BINDING_MISMATCH in _codes(rebound_result)
    assert untrusted_result.action == rebound_result.action == GuardAction.BLOCK


def test_detects_contradictory_retrieved_chunk_even_when_model_does_not_cite_it():
    issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")
    bundle = _bundle(issuer, domain=ImpactDomain.FINANCIAL)
    contradictory_chunk = CitationChunk.from_content(
        chunk_id="refunds:0",
        source=bundle.sources[0],
        content="Policy handbook.",
        ordinal=0,
    )
    retrieval = CitationRetrieval.from_metadata(
        retrieval_id=bundle.retrievals[0].retrieval_id,
        query="What is the refund window?",
        authorization_context="tenant:acme:user:42",
        chunk_ids=(bundle.chunks[0].chunk_id, contradictory_chunk.chunk_id),
        retrieved_at=NOW,
    )
    citation = issuer.issue(
        citation_id=bundle.citations[0].citation_id,
        response=RESPONSE,
        claim=bundle.claims[0],
        source=bundle.sources[0],
        chunk=bundle.chunks[0],
        retrieval=retrieval,
        transformation=bundle.transformations[0],
    )
    contradiction = ClaimEvidenceAssessment(
        claim_id=bundle.claims[0].claim_id,
        chunk_id=contradictory_chunk.chunk_id,
        claim_sha256=bundle.claims[0].text_sha256,
        chunk_sha256=contradictory_chunk.content_sha256,
        relation=EvidenceRelationKind.CONTRADICTS,
        confidence=0.92,
        assessor_id="entailment-service-v3",
    )

    result = _verifier(issuer).verify(
        bundle.model_copy(
            update={
                "chunks": (*bundle.chunks, contradictory_chunk),
                "retrievals": (retrieval,),
                "assessments": (*bundle.assessments, contradiction),
                "citations": (citation,),
            }
        ),
        now=NOW,
    )

    assert result.action == GuardAction.BLOCK
    assert CitationIntegrityCode.CONTRADICTED_CLAIM in _codes(result)


@pytest.mark.parametrize(
    ("bundle_updates", "expected"),
    [
        ({"confidence": 0.2}, CitationIntegrityCode.UNSUPPORTED_CLAIM),
        (
            {"relation": EvidenceRelationKind.CONTRADICTS},
            CitationIntegrityCode.CONTRADICTED_CLAIM,
        ),
        (
            {"retrieved_at": NOW - timedelta(days=31)},
            CitationIntegrityCode.STALE_EVIDENCE,
        ),
        (
            {"availability": SourceAvailability.INACCESSIBLE},
            CitationIntegrityCode.INACCESSIBLE_EVIDENCE,
        ),
    ],
)
def test_blocks_high_impact_claims_with_insufficient_evidence(bundle_updates, expected):
    issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")
    bundle = _bundle(issuer, domain=ImpactDomain.MEDICAL, **bundle_updates)

    result = _verifier(issuer).verify(bundle, now=NOW)

    assert result.action == GuardAction.BLOCK
    assert expected in _codes(result)


def test_can_downgrade_general_unsupported_claim_without_releasing_citation():
    issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")

    result = _verifier(issuer).verify(_bundle(issuer, confidence=0.2), now=NOW)

    assert result.action == GuardAction.WARN
    assert CitationIntegrityCode.UNSUPPORTED_CLAIM in _codes(result)
    assert not result.approved_citations


def test_policy_can_explicitly_downgrade_high_impact_insufficient_evidence():
    issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")
    bundle = _bundle(issuer, domain=ImpactDomain.FINANCIAL, confidence=0.2)

    release = _verifier(
        issuer,
        high_impact_insufficient_action=GuardAction.WARN,
    ).release(bundle, now=NOW)

    assert release.action == GuardAction.WARN
    assert not release.citations


def test_tampered_source_chunk_and_transformation_fail_closed():
    issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")
    bundle = _bundle(issuer)
    source = bundle.sources[0].model_copy(update={"snapshot": "attacker source"})
    chunk = bundle.chunks[0].model_copy(update={"content": "attacker chunk"})
    transformation = bundle.transformations[0].model_copy(update={"output": "attacker output"})

    result = _verifier(issuer).verify(
        bundle.model_copy(
            update={
                "sources": (source,),
                "chunks": (chunk,),
                "transformations": (transformation,),
            }
        ),
        now=NOW,
    )

    assert result.action == GuardAction.BLOCK
    assert CitationIntegrityCode.SOURCE_INTEGRITY_INVALID in _codes(result)
    assert CitationIntegrityCode.CHUNK_INTEGRITY_INVALID in _codes(result)
    assert CitationIntegrityCode.TRANSFORMATION_INTEGRITY_INVALID in _codes(result)


def test_blocked_diagnostics_and_exception_do_not_expose_source_or_response_text():
    issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")
    bundle = _bundle(issuer, domain=ImpactDomain.LEGAL, confidence=0.1)

    with pytest.raises(CitationIntegrityError) as exc_info:
        _verifier(issuer).release(bundle, now=NOW)

    serialized = exc_info.value.result.model_dump_json()
    assert RESPONSE not in serialized
    assert SOURCE_TEXT not in serialized
    assert CHUNK_TEXT not in serialized
    assert bundle.sources[0].source_uri not in serialized
    assert bundle.sources[0].source_id not in serialized


def test_evidence_models_reject_direct_digest_and_identity_bypass():
    source, chunk, retrieval, claim, _ = _components()

    with pytest.raises(ValidationError, match="snapshot integrity"):
        CitationSource(**{**source.model_dump(), "snapshot": "replacement"})
    with pytest.raises(ValidationError, match="chunk integrity"):
        CitationChunk(**{**chunk.model_dump(), "content": "replacement"})
    with pytest.raises(ValidationError, match="retrieval integrity"):
        CitationRetrieval(**{**retrieval.model_dump(), "chunk_ids": ("unknown",)})
    with pytest.raises(ValidationError, match="claim integrity"):
        CitationClaim(**{**claim.model_dump(), "text": "replacement"})


def test_verification_time_must_be_timezone_aware():
    issuer = CitationIssuer.generate(issuer_id="retrieval-gateway")

    with pytest.raises(ValueError, match="timezone-aware"):
        _verifier(issuer).verify(
            _bundle(issuer),
            now=datetime(2026, 9, 12, 12),
        )
