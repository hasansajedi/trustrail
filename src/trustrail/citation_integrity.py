"""Authority-signed citations and claim-to-chunk support verification."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from trustrail.exceptions import CitationIntegrityError
from trustrail.models.citation_integrity import (
    CitationChunk,
    CitationClaim,
    CitationEvidenceBundle,
    CitationIntegrityCode,
    CitationIntegrityFinding,
    CitationIntegrityPolicy,
    CitationIntegrityResult,
    CitationIntegritySignal,
    CitationRelease,
    CitationRetrieval,
    CitationSource,
    CitationTransformation,
    CitationTrustedKey,
    ClaimEvidenceAssessment,
    SourceAvailability,
    VerifiedCitation,
    citation_digest,
    citation_reference,
)
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.grounding import EvidenceRelationKind


class CitationIssuer:
    """Issue citations only from application-owned retrieval metadata."""

    def __init__(self, private_key: Ed25519PrivateKey, *, issuer_id: str) -> None:
        self._private_key = private_key
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._trusted_key = CitationTrustedKey(issuer_id=issuer_id, public_key=public_key)

    @classmethod
    def generate(cls, *, issuer_id: str) -> CitationIssuer:
        """Create an issuer backed by a newly generated Ed25519 key."""
        return cls(Ed25519PrivateKey.generate(), issuer_id=issuer_id)

    @property
    def trusted_key(self) -> CitationTrustedKey:
        """Return the public key binding for verifier configuration."""
        return self._trusted_key.model_copy(deep=True)

    def issue(
        self,
        *,
        citation_id: str,
        response: str,
        claim: CitationClaim,
        source: CitationSource,
        chunk: CitationChunk,
        retrieval: CitationRetrieval,
        transformation: CitationTransformation | None = None,
    ) -> VerifiedCitation:
        """Derive and sign an attribution from one authorized retrieval path."""
        if not claim.has_valid_integrity or claim.text not in response:
            raise ValueError("claim must be integrity-valid and present verbatim in the response")
        if not source.has_valid_integrity:
            raise ValueError("source snapshot integrity check failed")
        if not chunk.has_valid_integrity or chunk.content not in source.snapshot:
            raise ValueError("chunk must be integrity-valid content from the source snapshot")
        if (
            chunk.source_id != source.source_id
            or chunk.source_snapshot_sha256 != source.snapshot_sha256
        ):
            raise ValueError("chunk is not bound to the supplied source snapshot")
        if not retrieval.has_valid_integrity or chunk.chunk_id not in retrieval.chunk_ids:
            raise ValueError("chunk is absent from the authorized retrieval metadata")
        if transformation is not None and (
            not transformation.has_valid_integrity
            or transformation.input_chunk_id != chunk.chunk_id
            or transformation.input_sha256 != chunk.content_sha256
        ):
            raise ValueError("transformation is not bound to the supplied retrieved chunk")

        unsigned = VerifiedCitation(
            citation_id=citation_id,
            issuer_id=self._trusted_key.issuer_id,
            key_id=self._trusted_key.key_id,
            response_sha256=citation_digest(response),
            claim_id=claim.claim_id,
            claim_sha256=claim.text_sha256,
            source_id=source.source_id,
            source_uri=source.source_uri,
            source_snapshot_sha256=source.snapshot_sha256,
            chunk_id=chunk.chunk_id,
            chunk_sha256=chunk.content_sha256,
            retrieval_id=retrieval.retrieval_id,
            retrieval_sha256=retrieval.retrieval_sha256,
            transformation_id=(
                transformation.transformation_id if transformation is not None else None
            ),
            transformation_sha256=(
                transformation.evidence_sha256 if transformation is not None else None
            ),
        )
        return unsigned.model_copy(
            update={"signature": self._private_key.sign(unsigned.signing_bytes).hex()},
            deep=True,
        )


class CitationIntegrityVerifier:
    """Verify signed attribution and provider-neutral support before release."""

    def __init__(
        self,
        trusted_keys: Iterable[CitationTrustedKey],
        policy: CitationIntegrityPolicy,
    ) -> None:
        keys = tuple(key.model_copy(deep=True) for key in trusted_keys)
        self._trusted_keys = {key.key_id: key for key in keys}
        if not keys:
            raise ValueError("at least one trusted citation key is required")
        if len(keys) != len(self._trusted_keys):
            raise ValueError("trusted citation keys must have unique fingerprints")
        self._policy = policy.model_copy(deep=True)

    @property
    def policy(self) -> CitationIntegrityPolicy:
        """Return a defensive copy of the active verification policy."""
        return self._policy.model_copy(deep=True)

    def verify(
        self,
        bundle: CitationEvidenceBundle,
        *,
        now: datetime | None = None,
    ) -> CitationIntegrityResult:
        """Return a redacted decision for one complete response evidence bundle."""
        evaluated_at = now or datetime.now(tz=UTC)
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            raise ValueError("citation verification time must be timezone-aware")

        limit_finding = self._limit_finding(bundle)
        if limit_finding is not None:
            return CitationIntegrityResult(
                action=GuardAction.BLOCK,
                findings=(limit_finding,),
            )

        sources = {item.source_id: item for item in bundle.sources}
        chunks = {item.chunk_id: item for item in bundle.chunks}
        retrievals = {item.retrieval_id: item for item in bundle.retrievals}
        transformations = {item.transformation_id: item for item in bundle.transformations}
        claims = {item.claim_id: item for item in bundle.claims}

        findings: list[CitationIntegrityFinding] = []
        fatal = False
        for source_item in bundle.sources:
            if not source_item.has_valid_integrity:
                fatal = True
                findings.append(
                    self._finding(
                        CitationIntegrityCode.SOURCE_INTEGRITY_INVALID,
                        "A source snapshot differs from its captured digest",
                    )
                )
        for chunk_item in bundle.chunks:
            referenced_source = sources.get(chunk_item.source_id)
            if (
                not chunk_item.has_valid_integrity
                or referenced_source is None
                or chunk_item.source_snapshot_sha256 != referenced_source.snapshot_sha256
                or chunk_item.content not in referenced_source.snapshot
            ):
                fatal = True
                findings.append(
                    self._finding(
                        CitationIntegrityCode.CHUNK_INTEGRITY_INVALID,
                        "A chunk is not exact content from its bound source snapshot",
                    )
                )
        for retrieval in bundle.retrievals:
            if not retrieval.has_valid_integrity:
                fatal = True
                findings.append(
                    self._finding(
                        CitationIntegrityCode.RETRIEVAL_INTEGRITY_INVALID,
                        "Authorized retrieval metadata differs from its captured digest",
                    )
                )
        for transformation in bundle.transformations:
            input_chunk = chunks.get(transformation.input_chunk_id)
            if (
                not transformation.has_valid_integrity
                or input_chunk is None
                or transformation.input_sha256 != input_chunk.content_sha256
            ):
                fatal = True
                findings.append(
                    self._finding(
                        CitationIntegrityCode.TRANSFORMATION_INTEGRITY_INVALID,
                        "Transformation lineage is not bound to an exact retrieved chunk",
                    )
                )
        for claim_item in bundle.claims:
            if not claim_item.has_valid_integrity or claim_item.text not in bundle.response:
                fatal = True
                findings.append(
                    self._finding(
                        CitationIntegrityCode.CLAIM_INTEGRITY_INVALID,
                        "A claim is changed or absent from the response",
                        claim_id=claim_item.claim_id,
                    )
                )

        valid_citations: list[VerifiedCitation] = []
        for citation in bundle.citations:
            citation_findings = self._verify_citation(
                citation,
                response=bundle.response,
                claims=claims,
                sources=sources,
                chunks=chunks,
                retrievals=retrievals,
                transformations=transformations,
            )
            if citation_findings:
                fatal = True
                findings.extend(citation_findings)
            else:
                valid_citations.append(citation)

        valid_assessments: list[ClaimEvidenceAssessment] = []
        retrieved_chunk_ids = {
            chunk_id for retrieval in bundle.retrievals for chunk_id in retrieval.chunk_ids
        }
        for assessment in bundle.assessments:
            assessed_claim = claims.get(assessment.claim_id)
            assessed_chunk = chunks.get(assessment.chunk_id)
            if assessment.assessor_id not in self._policy.trusted_assessor_ids:
                fatal = True
                findings.append(
                    self._finding(
                        CitationIntegrityCode.UNTRUSTED_ASSESSOR,
                        "A support assessment was not produced by an approved assessor",
                        claim_id=assessment.claim_id,
                    )
                )
            elif (
                assessed_claim is None
                or assessed_chunk is None
                or assessment.claim_sha256 != assessed_claim.text_sha256
                or assessment.chunk_sha256 != assessed_chunk.content_sha256
            ):
                fatal = True
                findings.append(
                    self._finding(
                        CitationIntegrityCode.ASSESSMENT_BINDING_MISMATCH,
                        "A support assessment is not bound to the exact claim and chunk",
                        claim_id=assessment.claim_id,
                    )
                )
            elif assessment.chunk_id not in retrieved_chunk_ids:
                fatal = True
                findings.append(
                    self._finding(
                        CitationIntegrityCode.CHUNK_NOT_RETRIEVED,
                        "Assessed evidence was not present in an authorized retrieval event",
                        claim_id=assessment.claim_id,
                    )
                )
            else:
                valid_assessments.append(assessment)

        signals: list[CitationIntegritySignal] = []
        claims_with_quality_findings: set[str] = set()
        requested_action: Literal[
            GuardAction.ALLOW,
            GuardAction.WARN,
            GuardAction.BLOCK,
        ] = GuardAction.ALLOW
        for claim in bundle.claims:
            claim_findings, signal = self._evaluate_claim(
                claim,
                valid_citations=valid_citations,
                assessments=valid_assessments,
                sources=sources,
                chunks=chunks,
                retrievals=retrievals,
                now=evaluated_at,
            )
            signals.append(signal)
            if claim_findings:
                claims_with_quality_findings.add(claim.claim_id)
                findings.extend(claim_findings)
                configured_action = (
                    self._policy.high_impact_insufficient_action
                    if claim.impact_domain in self._policy.high_impact_domains
                    else self._policy.general_insufficient_action
                )
                if configured_action == GuardAction.BLOCK:
                    requested_action = GuardAction.BLOCK
                elif requested_action == GuardAction.ALLOW:
                    requested_action = GuardAction.WARN

        final_action: Literal[
            GuardAction.ALLOW,
            GuardAction.WARN,
            GuardAction.BLOCK,
        ] = GuardAction.BLOCK if fatal else requested_action
        approved = (
            tuple(
                item
                for item in valid_citations
                if item.claim_id not in claims_with_quality_findings
            )
            if final_action != GuardAction.BLOCK
            else ()
        )
        return CitationIntegrityResult(
            action=final_action,
            findings=tuple(findings),
            signals=tuple(signals),
            approved_citations=approved,
        )

    def release(
        self,
        bundle: CitationEvidenceBundle,
        *,
        now: datetime | None = None,
    ) -> CitationRelease:
        """Release the response and verified citations, or fail closed."""
        result = self.verify(bundle, now=now)
        if not result.is_releasable:
            raise CitationIntegrityError(result=result)
        release_action: Literal[GuardAction.ALLOW, GuardAction.WARN] = (
            GuardAction.WARN if result.action == GuardAction.WARN else GuardAction.ALLOW
        )
        return CitationRelease(
            response=bundle.response,
            action=release_action,
            citations=result.approved_citations,
            signals=result.signals,
        )

    def _verify_citation(
        self,
        citation: VerifiedCitation,
        *,
        response: str,
        claims: dict[str, CitationClaim],
        sources: dict[str, CitationSource],
        chunks: dict[str, CitationChunk],
        retrievals: dict[str, CitationRetrieval],
        transformations: dict[str, CitationTransformation],
    ) -> list[CitationIntegrityFinding]:
        findings: list[CitationIntegrityFinding] = []
        key = self._trusted_keys.get(citation.key_id)
        if key is None or key.revoked or key.issuer_id != citation.issuer_id:
            findings.append(
                self._finding(
                    CitationIntegrityCode.UNKNOWN_SIGNING_KEY,
                    "Citation issuer key is absent, revoked, or bound to another authority",
                    citation_id=citation.citation_id,
                )
            )
        elif citation.signature is None:
            findings.append(
                self._finding(
                    CitationIntegrityCode.CITATION_SIGNATURE_INVALID,
                    "Citation does not have a valid authority signature",
                    citation_id=citation.citation_id,
                )
            )
        else:
            try:
                Ed25519PublicKey.from_public_bytes(key.public_key).verify(
                    bytes.fromhex(citation.signature),
                    citation.signing_bytes,
                )
            except (InvalidSignature, ValueError):
                findings.append(
                    self._finding(
                        CitationIntegrityCode.CITATION_SIGNATURE_INVALID,
                        "Citation does not have a valid authority signature",
                        citation_id=citation.citation_id,
                    )
                )

        if citation.response_sha256 != citation_digest(response):
            findings.append(
                self._finding(
                    CitationIntegrityCode.RESPONSE_BINDING_MISMATCH,
                    "Citation is bound to a different response",
                    citation_id=citation.citation_id,
                )
            )
        claim = claims.get(citation.claim_id)
        if claim is None or citation.claim_sha256 != claim.text_sha256:
            findings.append(
                self._finding(
                    CitationIntegrityCode.CLAIM_BINDING_MISMATCH,
                    "Citation is not bound to an assessed response claim",
                    claim_id=citation.claim_id,
                    citation_id=citation.citation_id,
                )
            )
        source = sources.get(citation.source_id)
        if source is None or (
            citation.source_uri != source.source_uri
            or citation.source_snapshot_sha256 != source.snapshot_sha256
        ):
            findings.append(
                self._finding(
                    CitationIntegrityCode.SOURCE_BINDING_MISMATCH,
                    "Citation source attribution differs from the captured source snapshot",
                    citation_id=citation.citation_id,
                )
            )
        chunk = chunks.get(citation.chunk_id)
        if chunk is None or (
            citation.chunk_sha256 != chunk.content_sha256
            or citation.source_id != chunk.source_id
            or citation.source_snapshot_sha256 != chunk.source_snapshot_sha256
        ):
            findings.append(
                self._finding(
                    CitationIntegrityCode.CHUNK_BINDING_MISMATCH,
                    "Citation is not bound to an exact chunk from its source snapshot",
                    citation_id=citation.citation_id,
                )
            )
        retrieval = retrievals.get(citation.retrieval_id)
        if retrieval is None or citation.retrieval_sha256 != retrieval.retrieval_sha256:
            findings.append(
                self._finding(
                    CitationIntegrityCode.RETRIEVAL_BINDING_MISMATCH,
                    "Citation is not bound to the authorized retrieval event",
                    citation_id=citation.citation_id,
                )
            )
        elif citation.chunk_id not in retrieval.chunk_ids:
            findings.append(
                self._finding(
                    CitationIntegrityCode.CHUNK_NOT_RETRIEVED,
                    "Cited chunk was not present in the authorized retrieval event",
                    citation_id=citation.citation_id,
                )
            )
        if citation.transformation_id is not None:
            transformation = transformations.get(citation.transformation_id)
            if (
                transformation is None
                or citation.transformation_sha256 != transformation.evidence_sha256
                or transformation.input_chunk_id != citation.chunk_id
                or transformation.input_sha256 != citation.chunk_sha256
            ):
                findings.append(
                    self._finding(
                        CitationIntegrityCode.TRANSFORMATION_BINDING_MISMATCH,
                        "Citation transformation is not bound to its retrieved input chunk",
                        citation_id=citation.citation_id,
                    )
                )
        return findings

    def _evaluate_claim(
        self,
        claim: CitationClaim,
        *,
        valid_citations: Sequence[VerifiedCitation],
        assessments: Sequence[ClaimEvidenceAssessment],
        sources: dict[str, CitationSource],
        chunks: dict[str, CitationChunk],
        retrievals: dict[str, CitationRetrieval],
        now: datetime,
    ) -> tuple[list[CitationIntegrityFinding], CitationIntegritySignal]:
        citations = [item for item in valid_citations if item.claim_id == claim.claim_id]
        cited_chunk_ids = {item.chunk_id for item in citations}
        cited_assessments = [
            item
            for item in assessments
            if item.claim_id == claim.claim_id and item.chunk_id in cited_chunk_ids
        ]
        support_confidence = max(
            (
                item.confidence
                for item in cited_assessments
                if item.relation == EvidenceRelationKind.SUPPORTS
            ),
            default=0.0,
        )
        contradiction_confidence = max(
            (
                item.confidence
                for item in assessments
                if item.claim_id == claim.claim_id
                if item.relation == EvidenceRelationKind.CONTRADICTS
            ),
            default=0.0,
        )
        stale = any(
            (now - retrievals[item.retrieval_id].retrieved_at).total_seconds() < 0
            or (now - retrievals[item.retrieval_id].retrieved_at).total_seconds()
            > self._policy.max_evidence_age_seconds
            for item in citations
            if item.retrieval_id in retrievals
        )
        accessible = all(
            sources[chunks[chunk_id].source_id].availability == SourceAvailability.AVAILABLE
            for chunk_id in cited_chunk_ids
            if chunk_id in chunks and chunks[chunk_id].source_id in sources
        )
        findings: list[CitationIntegrityFinding] = []
        if not citations:
            findings.append(
                self._finding(
                    CitationIntegrityCode.ATTRIBUTION_MISSING,
                    "Material claim has no verified citation",
                    claim_id=claim.claim_id,
                )
            )
        if contradiction_confidence >= self._policy.contradiction_threshold:
            findings.append(
                self._finding(
                    CitationIntegrityCode.CONTRADICTED_CLAIM,
                    "Exact cited evidence contradicts the material claim",
                    claim_id=claim.claim_id,
                )
            )
        elif support_confidence < self._policy.minimum_support_confidence:
            findings.append(
                self._finding(
                    CitationIntegrityCode.UNSUPPORTED_CLAIM,
                    "Material claim lacks sufficient support from exact cited chunks",
                    claim_id=claim.claim_id,
                )
            )
        if stale:
            findings.append(
                self._finding(
                    CitationIntegrityCode.STALE_EVIDENCE,
                    "Cited retrieval evidence is outside the configured freshness window",
                    claim_id=claim.claim_id,
                )
            )
        if self._policy.require_accessible_sources and citations and not accessible:
            findings.append(
                self._finding(
                    CitationIntegrityCode.INACCESSIBLE_EVIDENCE,
                    "Cited source evidence is not currently accessible",
                    claim_id=claim.claim_id,
                )
            )
        return findings, CitationIntegritySignal(
            claim_reference=citation_reference(claim.claim_id),
            impact_domain=claim.impact_domain,
            support_confidence=support_confidence,
            contradiction_confidence=contradiction_confidence,
            cited_chunk_count=len(cited_chunk_ids),
            evidence_stale=stale,
            evidence_accessible=accessible,
        )

    def _limit_finding(
        self,
        bundle: CitationEvidenceBundle,
    ) -> CitationIntegrityFinding | None:
        if (
            len(bundle.response) > self._policy.max_response_chars
            or len(bundle.claims) > self._policy.max_claims
            or len(bundle.citations) > self._policy.max_citations
        ):
            return self._finding(
                CitationIntegrityCode.LIMIT_EXCEEDED,
                "Citation evidence exceeds a configured verification limit",
            )
        return None

    @staticmethod
    def _finding(
        code: CitationIntegrityCode,
        message: str,
        *,
        claim_id: str | None = None,
        citation_id: str | None = None,
    ) -> CitationIntegrityFinding:
        return CitationIntegrityFinding(
            code=code,
            severity=Severity.CRITICAL,
            message=message,
            claim_reference=citation_reference(claim_id) if claim_id is not None else None,
            citation_reference=(
                citation_reference(citation_id) if citation_id is not None else None
            ),
        )
