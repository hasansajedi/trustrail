# Misinformation and unsafe overreliance

OWASP LLM09:2025 covers plausible but false output and the risk that people or
downstream systems act on it without adequate verification. Text heuristics can
warn about absolute language, citation-shaped strings, high-risk advice, and
sycophancy. They cannot establish truth. Use `EvidenceGroundingVerifier` as the
typed release boundary for factual output and consequential recommendations.

## Security boundary

The verifier requires application-owned evidence and assessment data:

- each claim is an exact substring of the normalized output;
- evidence carries source identity, URI, trust, retrieval time, and a digest of
  the exact assessed content;
- a trusted assessor relates evidence to a claim as supporting, contradicting,
  or irrelevant, with its own confidence;
- citations bind claim-visible identifiers to exact evidence URI and digest;
- low model confidence must be disclosed to the user;
- high-impact claims need multiple independent source IDs and a time-bound,
  out-of-band human decision bound to the complete assessment;
- decisions and findings serialize without output, claim text, or evidence text.

Do not let the generating model assign its own source trust, assessor identity,
impact domain, evidence relation, or human-review outcome. Build those values
from protected application state and independently operated services.

## Verify a grounded response

```python
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
    source_uri="https://docs.example.com/refunds",
    content="The standard refund period is thirty days.",
    trust_level=TrustLevel.TRUSTED,
    retrieved_at=datetime.now(tz=UTC),
)
citation = GroundingCitation.from_evidence(
    citation_id="refund-policy",
    evidence=evidence,
)
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

safe_output = verifier.require(request)
```

`verify()` returns claim-level `GroundingSignal` values with support status,
model/support/contradiction confidence, evidence and source IDs, citation IDs,
uncertainty state, and review state. Use these signals for UI labels, audit
metrics, and downstream policy. Use `require()` at the final delivery or action
boundary; it raises `GroundingVerificationError` for both blocked and
review-required results.

## High-impact human review

Medical, legal, financial, security, safety, employment, and explicitly marked
high-impact claims require review by default. A disclaimer does not remove this
requirement. First verify the request without a grant. If its only finding is
`HUMAN_REVIEW_REQUIRED`, send the exact assessment to an independent reviewer.
After approval, attach a grant bound to that request:

```python
from datetime import UTC, datetime, timedelta

from trustrail import HumanReviewDecision, HumanReviewGrant

now = datetime.now(tz=UTC)
grant = HumanReviewGrant(
    review_id="review-891",
    request_id=request.request_id,
    reviewer_id="risk-reviewer",
    claim_ids=frozenset(claim.claim_id for claim in request.claims),
    assessment_sha256=request.assessment_sha256,
    decision=HumanReviewDecision.APPROVED,
    issued_at=now,
    expires_at=now + timedelta(minutes=15),
)
approved_request = request.model_copy(update={"human_review": grant})
safe_output = verifier.require(approved_request, now=now)
```

The assessment digest binds request ID, claim-text digests, claim metadata,
evidence provenance and digests, relations, and citations. A grant cannot be
reused after content, evidence, classification, or request identity changes.
Protect reviewer authentication and the approval channel independently; the
grant model is a validation contract, not an identity provider or signature.

## Decision behavior

`ALLOW` means all configured evidence, citation, uncertainty, and review checks
passed. `REQUIRE_APPROVAL` occurs only when the sole remaining condition is a
missing high-impact review. All malformed, contradictory, untrusted,
insufficient, stale-review, and incomplete-assessment cases return `BLOCK`.

The verifier also checks the complete output for normalized absolute language,
medical/legal/financial advice omitted from typed claim classification, and
citation-like text without provenance. This is defense in depth against an
incomplete claim extractor, not semantic fact checking.

## Operational guidance

- Obtain claims and relations from a separately evaluated grounding service or
  human workflow. Treat model self-reported confidence as untrusted input.
- Use authoritative, current, diverse sources. Count independent publishers or
  controlled datasets as different `source_id` values, not duplicate chunks of
  one document.
- Set `max_evidence_age_seconds` to a domain-appropriate freshness window; the
  default is 30 days, and future-dated evidence fails closed.
- Preserve evidence snapshots or immutable versions for audit. A URI alone can
  change after review.
- Calibrate model and assessor confidence against domain-specific held-out
  evaluations. A threshold copied between models is not meaningful evidence.
- Show uncertainty, source links, effective dates, and review status at the
  point where a user decides. Avoid UI language that implies guaranteed truth.
- Re-run verification after any generation, citation, evidence, policy, or
  transformation change. Apply destination-aware output handling afterward.
- Log identifiers, codes, confidence summaries, and digests. Do not log private
  output or evidence merely to diagnose a grounding failure.

## Limits and residual risk

This control reduces unsafe overreliance; it cannot prove a statement true.
Trusted sources can be stale, biased, compromised, mutually dependent, or wrong.
SHA-256 detects changes relative to captured bytes but does not authenticate a
publisher. Citation validation proves a binding to assessed evidence, not that
the evidence entails the claim. Automated relation assessors can hallucinate,
miss nuance, or share model failure modes with the generator.

The built-in text heuristics cover limited English phrases and citation forms.
They can miss paraphrases, specialized domains, tables, images, code behavior,
and multilingual claims. Domain classification must come from the application;
medical, legal, financial, security, employment, or safety impact can be
contextual even when no keyword appears.

Human reviewers can make mistakes or suffer automation bias. Give them the
original evidence, conflict indicators, uncertainty, and sufficient time;
separate reviewer incentives from automated throughput goals. For consequential
decisions, also require professional qualifications, appeal paths, monitoring,
and applicable legal or regulatory controls. Generated code and configuration
still require dependency verification, static/dynamic analysis, sandboxing, and
human review before execution.

Test the complete application with current domain corpora, known falsehoods,
fabricated and mismatched citations, contradictory sources, stale evidence,
confidence miscalibration, Unicode transformations, incomplete claim extraction,
and replayed approvals.
