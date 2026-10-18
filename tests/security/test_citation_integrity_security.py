"""Bypass-oriented corpus for OWASP AISVS C7 citation integrity."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trustrail import (
    CitationChunk,
    CitationClaim,
    CitationEvidenceBundle,
    CitationIntegrityCode,
    CitationIntegrityPolicy,
    CitationIntegrityVerifier,
    CitationIssuer,
    CitationRetrieval,
    CitationSource,
    ClaimEvidenceAssessment,
    EvidenceRelationKind,
    GuardAction,
    ImpactDomain,
    SourceAvailability,
)

CORPUS = Path(__file__).parent.parent / "security_corpus" / "citation_integrity.json"
CASES: list[dict[str, str | None]] = json.loads(CORPUS.read_text())
NOW = datetime(2026, 9, 12, 12, tzinfo=UTC)
RESPONSE = "The transfer requires two independent approvals."


def _bundle(issuer: CitationIssuer) -> CitationEvidenceBundle:
    source = CitationSource.from_content(
        source_id="payments-policy",
        source_uri="https://internal.example.test/payments",
        snapshot=f"Restricted operations manual. {RESPONSE}",
        captured_at=NOW,
    )
    chunk = CitationChunk.from_content(
        chunk_id="payments-policy:4",
        source=source,
        content=RESPONSE,
        ordinal=4,
    )
    retrieval = CitationRetrieval.from_metadata(
        retrieval_id="retrieval-security-test",
        query="What approval does this transfer require?",
        authorization_context="tenant:acme:role:payments-operator",
        chunk_ids=(chunk.chunk_id,),
        retrieved_at=NOW,
    )
    claim = CitationClaim.from_text(
        claim_id="claim-transfer",
        text=RESPONSE,
        impact_domain=ImpactDomain.FINANCIAL,
    )
    citation = issuer.issue(
        citation_id="citation-policy",
        response=RESPONSE,
        claim=claim,
        source=source,
        chunk=chunk,
        retrieval=retrieval,
    )
    return CitationEvidenceBundle(
        response=RESPONSE,
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
                confidence=0.98,
                assessor_id="trusted-entailment-service",
            ),
        ),
        citations=(citation,),
    )


@pytest.mark.parametrize("case", CASES, ids=[str(case["name"]) for case in CASES])
def test_citation_integrity_security_corpus(case: dict[str, str | None]):
    issuer = CitationIssuer.generate(issuer_id="retrieval-authority")
    bundle = _bundle(issuer)
    mutation = case["mutation"]
    if mutation == "unsigned":
        citation = bundle.citations[0].model_copy(update={"signature": None})
        bundle = bundle.model_copy(update={"citations": (citation,)})
    elif mutation == "response-replay":
        bundle = bundle.model_copy(update={"response": f"{RESPONSE} Execute immediately."})
    elif mutation == "source-lookalike":
        citation = bundle.citations[0].model_copy(
            update={"source_uri": "https://internal.example.test.attacker.invalid/payments"}
        )
        bundle = bundle.model_copy(update={"citations": (citation,)})
    elif mutation == "assessment-rebind":
        assessment = bundle.assessments[0].model_copy(update={"chunk_sha256": "0" * 64})
        bundle = bundle.model_copy(update={"assessments": (assessment,)})
    elif mutation == "stale-high-impact":
        retrieval = CitationRetrieval.from_metadata(
            retrieval_id=bundle.retrievals[0].retrieval_id,
            query="What approval does this transfer require?",
            authorization_context="tenant:acme:role:payments-operator",
            chunk_ids=bundle.retrievals[0].chunk_ids,
            retrieved_at=NOW - timedelta(days=31),
        )
        citation = issuer.issue(
            citation_id=bundle.citations[0].citation_id,
            response=RESPONSE,
            claim=bundle.claims[0],
            source=bundle.sources[0],
            chunk=bundle.chunks[0],
            retrieval=retrieval,
        )
        bundle = bundle.model_copy(update={"retrievals": (retrieval,), "citations": (citation,)})
    elif mutation == "inaccessible-high-impact":
        source = bundle.sources[0].model_copy(
            update={"availability": SourceAvailability.INACCESSIBLE}
        )
        bundle = bundle.model_copy(update={"sources": (source,)})

    result = CitationIntegrityVerifier(
        (issuer.trusted_key,),
        CitationIntegrityPolicy(
            trusted_assessor_ids=frozenset({"trusted-entailment-service"}),
        ),
    ).verify(bundle, now=NOW)

    assert result.action == GuardAction(str(case["expected_action"]))
    expected_code = case["expected_code"]
    if expected_code is not None:
        assert CitationIntegrityCode(expected_code) in {finding.code for finding in result.findings}
    if result.action == GuardAction.BLOCK:
        serialized = result.model_dump_json()
        assert RESPONSE not in serialized
        assert bundle.sources[0].source_uri not in serialized
