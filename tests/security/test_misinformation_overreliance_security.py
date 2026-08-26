"""Bypass-oriented security corpus for OWASP LLM09:2025."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
    GroundingVerificationCode,
    GuardAction,
    HumanReviewDecision,
    HumanReviewGrant,
    ImpactDomain,
    TrustLevel,
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "misinformation_overreliance.json"
CASES: list[dict[str, str | None]] = json.loads(CORPUS_PATH.read_text())
NOW = datetime(2026, 8, 26, 12, tzinfo=UTC)
OUTPUT = "The reviewed handbook states that refunds are available for thirty days."


def _request(*, domain: ImpactDomain = ImpactDomain.GENERAL, sources: int = 1) -> GroundingRequest:
    evidence = tuple(
        GroundingEvidence.from_content(
            evidence_id=f"evidence-{index}",
            source_id=f"source-{index}",
            source_uri=f"https://evidence.example.test/{index}",
            content=f"Independent source {index}: {OUTPUT}",
            trust_level=TrustLevel.TRUSTED,
            retrieved_at=NOW,
        )
        for index in range(1, sources + 1)
    )
    citations = tuple(
        GroundingCitation.from_evidence(citation_id=f"citation-{index}", evidence=item)
        for index, item in enumerate(evidence, start=1)
    )
    claim = GroundingClaim(
        claim_id="claim-1",
        text=OUTPUT,
        kind=ClaimKind.FACT,
        impact_domain=domain,
        model_confidence=0.95,
        citation_ids=frozenset(citation.citation_id for citation in citations),
    )
    return GroundingRequest(
        request_id="security-request",
        output=OUTPUT,
        claims=(claim,),
        evidence=evidence,
        relations=tuple(
            EvidenceRelation(
                claim_id=claim.claim_id,
                evidence_id=item.evidence_id,
                relation=EvidenceRelationKind.SUPPORTS,
                confidence=0.95,
                assessor_id="trusted-assessor",
            )
            for item in evidence
        ),
        citations=citations,
    )


def _review(request: GroundingRequest, *, replayed: bool = False, expired: bool = False):
    return HumanReviewGrant(
        review_id="review-1",
        request_id="another-request" if replayed else request.request_id,
        reviewer_id="trusted-reviewer",
        claim_ids=frozenset({"claim-1"}),
        assessment_sha256=request.assessment_sha256,
        decision=HumanReviewDecision.APPROVED,
        issued_at=NOW - timedelta(minutes=10),
        expires_at=NOW - timedelta(minutes=1) if expired else NOW + timedelta(minutes=10),
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: str(case["name"]))
def test_misinformation_overreliance_security_corpus(case: dict[str, str | None]):
    mutation = case["mutation"]
    high_impact = mutation in {
        "single-high-impact-source",
        "review-required",
        "review-replay",
        "review-expired",
    }
    sources = 2 if high_impact and mutation != "single-high-impact-source" else 1
    request = _request(
        domain=ImpactDomain.MEDICAL if high_impact else ImpactDomain.GENERAL,
        sources=sources,
    )

    if mutation == "unknown-citation":
        claim = request.claims[0].model_copy(update={"citation_ids": frozenset({"fake"})})
        request = request.model_copy(update={"claims": (claim,)})
    elif mutation == "citation-uri":
        citation = request.citations[0].model_copy(
            update={"source_uri": "https://evidence.example.test/1.evil"}
        )
        request = request.model_copy(update={"citations": (citation,)})
    elif mutation == "evidence-content":
        evidence = request.evidence[0].model_copy(update={"content": "replaced evidence"})
        request = request.model_copy(update={"evidence": (evidence,)})
    elif mutation == "stale-evidence":
        evidence = request.evidence[0].model_copy(update={"retrieved_at": NOW - timedelta(days=31)})
        request = request.model_copy(update={"evidence": (evidence,)})
    elif mutation == "assessor":
        relation = request.relations[0].model_copy(update={"assessor_id": "model-self-check"})
        request = request.model_copy(update={"relations": (relation,)})
    elif mutation == "contradiction":
        relation = request.relations[0].model_copy(
            update={"relation": EvidenceRelationKind.CONTRADICTS}
        )
        request = request.model_copy(update={"relations": (relation,)})
    elif mutation == "unicode-absolute":
        request = request.model_copy(update={"output": f"{OUTPUT} This al\u200bways works."})
    elif mutation == "unclassified-medical":
        request = request.model_copy(
            update={"output": f"{OUTPUT} You should take ibuprofen 800mg."}
        )
    elif mutation == "hidden-uncertainty":
        claim = request.claims[0].model_copy(update={"model_confidence": 0.1})
        request = request.model_copy(update={"claims": (claim,)})
    elif mutation in {"review-replay", "review-expired"}:
        request = request.model_copy(
            update={
                "human_review": _review(
                    request,
                    replayed=mutation == "review-replay",
                    expired=mutation == "review-expired",
                )
            }
        )

    result = EvidenceGroundingVerifier(
        GroundingPolicy(
            trusted_assessor_ids=frozenset({"trusted-assessor"}),
            trusted_reviewer_ids=frozenset({"trusted-reviewer"}),
        )
    ).verify(request, now=NOW)

    assert result.action == GuardAction(str(case["expected_action"]))
    expected_code = case["expected_code"]
    if expected_code is not None:
        assert GroundingVerificationCode(expected_code) in {
            finding.code for finding in result.findings
        }
    assert OUTPUT not in result.model_dump_json()
