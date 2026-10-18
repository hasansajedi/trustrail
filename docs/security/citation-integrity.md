# Citation and claim integrity

OWASP AISVS C7 requires source attribution to come from retrieved evidence, not
from plausible-looking model prose. `CitationIssuer` and
`CitationIntegrityVerifier` provide a typed release boundary for RAG responses:
the retrieval authority issues an Ed25519-signed attribution, and the response
service verifies both the attribution chain and independent claim support before
showing it.

Use this control after retrieval and generation. Continue to use document
scanning, vector authorization, output handling, and structured-output validation
at their own boundaries.

## Evidence chain

The bundle keeps each security fact separate and integrity-bound:

- `CitationSource` captures a source URI, exact snapshot, capture time, current
  availability, stable source ID, and domain-separated SHA-256 digest;
- `CitationChunk` binds exact chunk bytes and ordinal to that source snapshot;
- `CitationRetrieval` records hashed query and authorization context references,
  retrieval time, the returned chunk IDs, and a digest of the full event;
- `CitationTransformation` optionally records the input chunk digest, operation,
  transformer identity, and exact output digest;
- `CitationClaim` binds a material claim and impact domain to its exact text;
- `ClaimEvidenceAssessment` expresses provider-neutral support, contradiction,
  or irrelevance for one exact claim/chunk pair; and
- `VerifiedCitation` is signed by the retrieval authority over the response,
  claim, source snapshot, chunk, retrieval, and optional transformation digests.

Source, chunk, claim, and response text are excluded from normal Pydantic
serialization. A blocked result contains hashed claim/citation references and
codes, never the response, source text, chunk text, query, authorization context,
or source URI.

## Recommended flow

1. Capture source snapshots and chunks in the trusted retrieval service.
2. Build `CitationRetrieval` with the authenticated authorization context. Its
   raw query and context are hashed and not retained by the model.
3. Generate the response, extract material claims, and obtain semantic
   claim/chunk assessments from a separately evaluated provider or human process.
4. Call `CitationIssuer.issue()` in the retrieval authority. It refuses chunks
   absent from the retrieval event, chunks outside the source snapshot, claims
   absent from the response, and broken transformation lineage.
5. Assemble `CitationEvidenceBundle` and call
   `CitationIntegrityVerifier.release()` immediately before display or use.
6. Render only the citations in `CitationRelease.citations`. Never render the
   model's own source strings or the unverified bundle citations.

See the complete offline
[`citation_integrity.py`](https://github.com/hasansajedi/trustrail/blob/main/examples/citation_integrity.py)
example.

## Policy and failure behavior

```python
from trustrail import CitationIntegrityPolicy, GuardAction

policy = CitationIntegrityPolicy(
    trusted_assessor_ids=frozenset({"entailment-service-v3"}),
    minimum_support_confidence=0.85,
    contradiction_threshold=0.60,
    max_evidence_age_seconds=86_400,
    require_accessible_sources=True,
    general_insufficient_action=GuardAction.WARN,
    high_impact_insufficient_action=GuardAction.BLOCK,
)
```

Signature, identity, response, source, chunk, retrieval, transformation, or
assessment-binding failures always block. Evidence-quality failures—missing
attribution, insufficient support, contradiction, staleness, or inaccessibility—
use the configured impact-aware action. The defaults warn for general claims and
block medical, legal, financial, security, safety, employment, and other
high-impact claims. A warning releases the response without citations for the
affected claim, preventing a weak attribution from retaining a verified appearance.

Set `high_impact_insufficient_action=GuardAction.WARN` only when your application
has a visibly degraded, non-actionable presentation. For decisions or automated
actions, keep the fail-closed default and combine it with qualified human review.

## Security assumptions

- Keep issuer private keys outside the model and generation process. Distribute
  `CitationTrustedKey` objects through an authenticated configuration channel.
- Derive retrieval authorization from authenticated server state. Prompt text,
  model output, and vector-store metadata are not authorization evidence.
- Trust assessor IDs only when the caller authentication and deployment identity
  actually prove them. The string alone is not authentication.
- Re-check current source accessibility and freshness at release time. Preserve
  immutable snapshots for audit and dispute handling.
- Run material-claim extraction independently and test coverage. An omitted claim
  cannot be verified by a claim-to-chunk control.
- Rotate and revoke issuer keys through protected operational configuration. A
  revoked key is rejected, but this library does not distribute revocation state.

## Limitations and residual risk

Cryptographic binding proves which metadata an authorized issuer signed; it does
not prove that a publisher is honest, a source is correct, or an assessor
understands the claim. SHA-256 detects changes relative to captured bytes but
does not authenticate the source publisher. Ed25519 does not protect a
compromised issuer service or stolen private key.

Support confidence must be calibrated for each domain, language, model, and
content type. Text containment does not validate OCR, images, tables, or dynamic
pages. Source availability is supplied by the application and must come from a
trusted fetch/access check. Multiple chunks from one publisher are not
independent evidence. Transformations can preserve digest lineage while still
changing meaning. Claims can also be materially misleading through omissions or
framing even when each sentence is entailed.

For high-impact decisions, retain professional review, appeals, source-quality
policy, monitoring, and applicable legal controls. Test fabricated citations,
lookalike URLs, response replay, chunk substitution, stale and inaccessible
sources, compromised assessors, missing claims, Unicode variants, and key
rotation in the complete deployed pipeline.
