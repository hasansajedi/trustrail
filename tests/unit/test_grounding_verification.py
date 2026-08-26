"""Unit tests for OWASP LLM09 evidence-backed grounding controls."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

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
    GroundingVerificationError,
    GuardAction,
    HumanReviewDecision,
    HumanReviewGrant,
    ImpactDomain,
    TrustLevel,
)

NOW = datetime(2026, 8, 26, 12, tzinfo=UTC)
OUTPUT = "The approved refund period is thirty days."


def _evidence(
    number: int = 1,
    *,
    trust_level: TrustLevel = TrustLevel.TRUSTED,
) -> GroundingEvidence:
    return GroundingEvidence.from_content(
        evidence_id=f"evidence-{number}",
        source_id=f"source-{number}",
        source_uri=f"https://docs.example.test/policy-{number}",
        content=f"Source {number}: {OUTPUT}",
        trust_level=trust_level,
        retrieved_at=NOW,
    )


def _policy(**updates: object) -> GroundingPolicy:
    values: dict[str, object] = {
        "trusted_assessor_ids": frozenset({"fact-checker-v1"}),
        "trusted_reviewer_ids": frozenset({"reviewer-1"}),
    }
    values.update(updates)
    return GroundingPolicy(**values)


def _request(
    *,
    output: str = OUTPUT,
    domain: ImpactDomain = ImpactDomain.GENERAL,
    confidence: float = 0.95,
    uncertainty_disclosed: bool = False,
    evidence_count: int = 1,
    relation_kind: EvidenceRelationKind = EvidenceRelationKind.SUPPORTS,
    relation_confidence: float = 0.95,
    assessor_id: str = "fact-checker-v1",
    citations: bool = True,
) -> GroundingRequest:
    evidence = tuple(_evidence(number) for number in range(1, evidence_count + 1))
    citation_items = tuple(
        GroundingCitation.from_evidence(citation_id=f"citation-{number}", evidence=item)
        for number, item in enumerate(evidence, start=1)
    )
    claim = GroundingClaim(
        claim_id="claim-1",
        text=OUTPUT,
        kind=ClaimKind.FACT,
        impact_domain=domain,
        model_confidence=confidence,
        uncertainty_disclosed=uncertainty_disclosed,
        citation_ids=(
            frozenset(item.citation_id for item in citation_items) if citations else frozenset()
        ),
    )
    return GroundingRequest(
        request_id="request-1",
        output=output,
        claims=(claim,),
        evidence=evidence,
        relations=tuple(
            EvidenceRelation(
                claim_id=claim.claim_id,
                evidence_id=item.evidence_id,
                relation=relation_kind,
                confidence=relation_confidence,
                assessor_id=assessor_id,
            )
            for item in evidence
        ),
        citations=citation_items if citations else (),
    )


def _reviewed(request: GroundingRequest, **updates: object) -> GroundingRequest:
    values: dict[str, object] = {
        "review_id": "review-1",
        "request_id": request.request_id,
        "reviewer_id": "reviewer-1",
        "claim_ids": frozenset(claim.claim_id for claim in request.claims),
        "assessment_sha256": request.assessment_sha256,
        "decision": HumanReviewDecision.APPROVED,
        "issued_at": NOW - timedelta(minutes=5),
        "expires_at": NOW + timedelta(minutes=30),
    }
    values.update(updates)
    return request.model_copy(update={"human_review": HumanReviewGrant(**values)})


def _codes(result: object) -> set[GroundingVerificationCode]:
    return {finding.code for finding in result.findings}  # type: ignore[attr-defined]


def test_allows_supported_claim_and_exposes_content_free_provenance_signal():
    result = EvidenceGroundingVerifier(_policy()).verify(_request(), now=NOW)

    assert result.action == GuardAction.ALLOW
    assert result.approved_output == OUTPUT
    assert result.signals[0].evidence_ids == ("evidence-1",)
    assert result.signals[0].source_ids == ("source-1",)
    assert result.signals[0].support_confidence == 0.95
    assert OUTPUT not in result.model_dump_json()
    assert OUTPUT not in _request().model_dump_json()


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("missing", GroundingVerificationCode.UNKNOWN_CITATION),
        ("uri", GroundingVerificationCode.CITATION_MISMATCH),
        ("digest", GroundingVerificationCode.CITATION_MISMATCH),
    ],
)
def test_rejects_fabricated_or_mismatched_citations(
    mutation: str,
    expected_code: GroundingVerificationCode,
):
    request = _request()
    if mutation == "missing":
        claim = request.claims[0].model_copy(update={"citation_ids": frozenset({"invented"})})
        request = request.model_copy(update={"claims": (claim,)})
    else:
        update = (
            {"source_uri": "https://docs.example.test/policy-1.evil"}
            if mutation == "uri"
            else {"evidence_sha256": "0" * 64}
        )
        citation = request.citations[0].model_copy(update=update)
        request = request.model_copy(update={"citations": (citation,)})

    result = EvidenceGroundingVerifier(_policy()).verify(request, now=NOW)

    assert result.is_blocked
    assert expected_code in _codes(result)


def test_rejects_absolute_unsupported_and_contradicted_claims():
    absolute = "This treatment is absolutely certain to work."
    request = _request(
        output=absolute,
        relation_kind=EvidenceRelationKind.IRRELEVANT,
    )
    claim = request.claims[0].model_copy(update={"text": absolute})
    request = request.model_copy(update={"claims": (claim,)})

    unsupported = EvidenceGroundingVerifier(_policy()).verify(request, now=NOW)
    contradicted = EvidenceGroundingVerifier(_policy()).verify(
        _request(relation_kind=EvidenceRelationKind.CONTRADICTS),
        now=NOW,
    )

    assert GroundingVerificationCode.ABSOLUTE_CLAIM_UNSUPPORTED in _codes(unsupported)
    assert GroundingVerificationCode.CONTRADICTED_CLAIM in _codes(contradicted)


def test_requires_uncertainty_disclosure_below_policy_threshold():
    hidden = EvidenceGroundingVerifier(_policy()).verify(
        _request(confidence=0.5),
        now=NOW,
    )
    disclosed = EvidenceGroundingVerifier(_policy()).verify(
        _request(confidence=0.5, uncertainty_disclosed=True),
        now=NOW,
    )

    assert GroundingVerificationCode.UNCERTAINTY_NOT_DISCLOSED in _codes(hidden)
    assert disclosed.is_allowed


def test_rejects_evidence_changed_after_capture_and_low_trust_evidence():
    request = _request()
    changed = request.evidence[0].model_copy(update={"content": "attacker replacement"})
    changed_request = request.model_copy(update={"evidence": (changed,)})
    low_trust = _request().model_copy(
        update={"evidence": (_evidence(trust_level=TrustLevel.UNTRUSTED),)}
    )

    changed_result = EvidenceGroundingVerifier(_policy()).verify(changed_request, now=NOW)
    low_trust_result = EvidenceGroundingVerifier(_policy()).verify(low_trust, now=NOW)

    assert GroundingVerificationCode.BROKEN_EVIDENCE_INTEGRITY in _codes(changed_result)
    assert GroundingVerificationCode.EVIDENCE_TRUST_TOO_LOW in _codes(low_trust_result)


@pytest.mark.parametrize(
    ("retrieved_at", "expected_code"),
    [
        (NOW - timedelta(days=31), GroundingVerificationCode.EVIDENCE_STALE),
        (NOW + timedelta(seconds=1), GroundingVerificationCode.EVIDENCE_FROM_FUTURE),
    ],
)
def test_rejects_stale_or_future_dated_evidence(
    retrieved_at: datetime,
    expected_code: GroundingVerificationCode,
):
    request = _request()
    evidence = request.evidence[0].model_copy(update={"retrieved_at": retrieved_at})
    request = request.model_copy(update={"evidence": (evidence,)})

    result = EvidenceGroundingVerifier(_policy()).verify(request, now=NOW)

    assert expected_code in _codes(result)


def test_rejects_untrusted_relation_assessor():
    result = EvidenceGroundingVerifier(_policy()).verify(
        _request(assessor_id="model-self-assessment"),
        now=NOW,
    )

    assert GroundingVerificationCode.UNTRUSTED_ASSESSOR in _codes(result)
    assert GroundingVerificationCode.UNSUPPORTED_CLAIM in _codes(result)


def test_high_impact_claim_requires_independent_sources_then_human_review():
    verifier = EvidenceGroundingVerifier(_policy())

    insufficient = verifier.verify(
        _request(domain=ImpactDomain.MEDICAL),
        now=NOW,
    )
    awaiting_review = verifier.verify(
        _request(domain=ImpactDomain.MEDICAL, evidence_count=2),
        now=NOW,
    )

    assert insufficient.is_blocked
    assert GroundingVerificationCode.HIGH_IMPACT_EVIDENCE_INSUFFICIENT in _codes(insufficient)
    assert awaiting_review.action == GuardAction.REQUIRE_APPROVAL
    assert GroundingVerificationCode.HUMAN_REVIEW_REQUIRED in _codes(awaiting_review)


def test_valid_bound_human_review_allows_high_impact_claim():
    request = _request(domain=ImpactDomain.MEDICAL, evidence_count=2)

    result = EvidenceGroundingVerifier(_policy()).verify(_reviewed(request), now=NOW)

    assert result.is_allowed
    assert result.signals[0].human_reviewed


@pytest.mark.parametrize(
    "updates",
    [
        {"reviewer_id": "untrusted-reviewer"},
        {"assessment_sha256": "0" * 64},
        {"request_id": "different-request"},
        {"expires_at": NOW - timedelta(minutes=1)},
    ],
)
def test_rejects_untrusted_expired_or_replayed_human_review(updates: dict[str, object]):
    request = _request(domain=ImpactDomain.MEDICAL, evidence_count=2)

    result = EvidenceGroundingVerifier(_policy()).verify(
        _reviewed(request, **updates),
        now=NOW,
    )

    assert result.is_blocked
    assert GroundingVerificationCode.HUMAN_REVIEW_INVALID in _codes(result)


def test_reviewer_rejection_blocks_high_impact_claim():
    request = _request(domain=ImpactDomain.MEDICAL, evidence_count=2)
    result = EvidenceGroundingVerifier(_policy()).verify(
        _reviewed(request, decision=HumanReviewDecision.REJECTED),
        now=NOW,
    )

    assert GroundingVerificationCode.HUMAN_REVIEW_REJECTED in _codes(result)


@pytest.mark.parametrize(
    ("output", "expected_code"),
    [
        (
            f"{OUTPUT} This always works in production.",
            GroundingVerificationCode.ABSOLUTE_CLAIM_UNASSESSED,
        ),
        (
            f"{OUTPUT} You should take ibuprofen 800mg.",
            GroundingVerificationCode.HIGH_IMPACT_DOMAIN_UNCLASSIFIED,
        ),
        (
            f"{OUTPUT} See doi:10.1000/fabricated.",
            GroundingVerificationCode.UNVERIFIED_CITATION,
        ),
    ],
)
def test_blocks_dangerous_output_omitted_from_claim_assessment(
    output: str,
    expected_code: GroundingVerificationCode,
):
    request = _request(output=output)
    if expected_code == GroundingVerificationCode.UNVERIFIED_CITATION:
        claim = request.claims[0].model_copy(update={"citation_ids": frozenset()})
        request = request.model_copy(update={"claims": (claim,), "citations": ()})

    result = EvidenceGroundingVerifier(_policy()).verify(request, now=NOW)

    assert result.is_blocked
    assert expected_code in _codes(result)


def test_require_fails_closed_without_exposing_output_in_exception_result():
    request = _request(relation_kind=EvidenceRelationKind.IRRELEVANT)

    with pytest.raises(GroundingVerificationError) as exc_info:
        EvidenceGroundingVerifier(_policy()).require(request, now=NOW)

    assert OUTPUT not in exc_info.value.result.model_dump_json()


def test_models_reject_duplicate_ids_and_invalid_review_windows():
    request = _request()
    with pytest.raises(ValidationError, match="duplicate evidence IDs"):
        GroundingRequest(
            request_id=request.request_id,
            output=request.output,
            claims=request.claims,
            evidence=request.evidence * 2,
            relations=request.relations,
            citations=request.citations,
        )
    with pytest.raises(ValidationError, match="expiration must follow issuance"):
        HumanReviewGrant(
            review_id="review-1",
            request_id="request-1",
            reviewer_id="reviewer-1",
            claim_ids=frozenset({"claim-1"}),
            assessment_sha256="0" * 64,
            decision=HumanReviewDecision.APPROVED,
            issued_at=NOW,
            expires_at=NOW,
        )


def test_policy_requires_independent_assessor_and_reviewer_identities():
    with pytest.raises(ValidationError, match="must be independent"):
        GroundingPolicy(
            trusted_assessor_ids=frozenset({"same-person"}),
            trusted_reviewer_ids=frozenset({"same-person"}),
        )


def test_verification_time_must_be_timezone_aware():
    with pytest.raises(ValueError, match="timezone-aware"):
        EvidenceGroundingVerifier(_policy()).verify(
            _request(),
            now=datetime(2026, 8, 26, 12),
        )
