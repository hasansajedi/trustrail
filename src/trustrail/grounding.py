"""Evidence-backed claim verification and overreliance controls."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Literal

from trustrail.exceptions import GroundingVerificationError
from trustrail.models.enums import GuardAction, Severity, TrustLevel
from trustrail.models.grounding import (
    EvidenceRelation,
    EvidenceRelationKind,
    GroundingCitation,
    GroundingClaim,
    GroundingEvidence,
    GroundingFinding,
    GroundingPolicy,
    GroundingRequest,
    GroundingResult,
    GroundingSignal,
    GroundingSupportStatus,
    GroundingVerificationCode,
    HumanReviewDecision,
    ImpactDomain,
)
from trustrail.normalization import TextNormalizer
from trustrail.rules.output.grounding_rules import (
    contains_absolute_claim,
    contains_citation_candidate,
    detect_high_risk_domain,
)

_WHITESPACE_RE = re.compile(r"\s+")
_TRUST_ORDER = {
    TrustLevel.UNTRUSTED: 0,
    TrustLevel.SEMI_TRUSTED: 1,
    TrustLevel.TRUSTED: 2,
}
_DETECTED_DOMAIN = {
    "medical": ImpactDomain.MEDICAL,
    "legal": ImpactDomain.LEGAL,
    "financial": ImpactDomain.FINANCIAL,
}


class EvidenceGroundingVerifier:
    """Validate support, citations, contradictions, uncertainty, and review."""

    def __init__(self, policy: GroundingPolicy) -> None:
        self._policy = policy.model_copy(deep=True)
        self._normalizer = TextNormalizer()

    @property
    def policy(self) -> GroundingPolicy:
        """Return a defensive copy of the active grounding policy."""
        return self._policy.model_copy(deep=True)

    def verify(
        self,
        request: GroundingRequest,
        *,
        now: datetime | None = None,
    ) -> GroundingResult:
        """Return a content-free decision and claim-level provenance signals."""
        evaluated_at = now or datetime.now(tz=UTC)
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            raise ValueError("grounding verification time must be timezone-aware")
        findings = self._limit_findings(request)
        if findings:
            return self._result(request, findings=findings)

        claims = {claim.claim_id: claim for claim in request.claims}
        evidence = {item.evidence_id: item for item in request.evidence}
        citations = {citation.citation_id: citation for citation in request.citations}

        findings.extend(self._evidence_findings(request.evidence, evaluated_at))
        findings.extend(self._relation_findings(request.relations, claims, evidence))
        findings.extend(self._citation_findings(request.citations, citations, evidence, claims))

        normalized_output = self._normalize(request.output)
        valid_review, review_findings = self._review_state(request, evaluated_at)
        findings.extend(review_findings)

        signals: list[GroundingSignal] = []
        for claim in request.claims:
            claim_findings, signal = self._evaluate_claim(
                claim,
                request=request,
                normalized_output=normalized_output,
                evidence=evidence,
                citations=citations,
                valid_review=valid_review,
            )
            findings.extend(claim_findings)
            signals.append(signal)

        findings.extend(self._output_coverage_findings(request))
        return self._result(request, findings=findings, signals=signals)

    def require(self, request: GroundingRequest, *, now: datetime | None = None) -> str:
        """Return verified output or raise before display or high-impact use."""
        result = self.verify(request, now=now)
        if not result.is_allowed or result.approved_output is None:
            raise GroundingVerificationError(result=result)
        return result.approved_output

    def _limit_findings(self, request: GroundingRequest) -> list[GroundingFinding]:
        findings: list[GroundingFinding] = []
        if len(request.output) > self._policy.max_output_chars:
            findings.append(
                self._finding(
                    GroundingVerificationCode.OUTPUT_TOO_LARGE,
                    "Generated output exceeds the configured grounding limit",
                )
            )
        if len(request.claims) > self._policy.max_claims:
            findings.append(
                self._finding(
                    GroundingVerificationCode.CLAIM_LIMIT_EXCEEDED,
                    "Claim count exceeds the configured grounding limit",
                )
            )
        if len(request.evidence) > self._policy.max_evidence_items:
            findings.append(
                self._finding(
                    GroundingVerificationCode.EVIDENCE_LIMIT_EXCEEDED,
                    "Evidence count exceeds the configured grounding limit",
                )
            )
        return findings

    def _evidence_findings(
        self,
        evidence: Sequence[GroundingEvidence],
        now: datetime,
    ) -> list[GroundingFinding]:
        findings: list[GroundingFinding] = []
        required_trust = _TRUST_ORDER[self._policy.minimum_evidence_trust]
        for item in evidence:
            if not item.has_valid_integrity:
                findings.append(
                    self._finding(
                        GroundingVerificationCode.BROKEN_EVIDENCE_INTEGRITY,
                        "Evidence differs from its captured integrity digest",
                    )
                )
            if _TRUST_ORDER[item.trust_level] < required_trust:
                findings.append(
                    self._finding(
                        GroundingVerificationCode.EVIDENCE_TRUST_TOO_LOW,
                        "Evidence trust is below the configured grounding requirement",
                    )
                )
            age_seconds = (now - item.retrieved_at).total_seconds()
            if age_seconds < 0:
                findings.append(
                    self._finding(
                        GroundingVerificationCode.EVIDENCE_FROM_FUTURE,
                        "Evidence retrieval time is later than verification time",
                    )
                )
            elif age_seconds > self._policy.max_evidence_age_seconds:
                findings.append(
                    self._finding(
                        GroundingVerificationCode.EVIDENCE_STALE,
                        "Evidence exceeds the configured grounding freshness window",
                    )
                )
        return findings

    def _relation_findings(
        self,
        relations: Sequence[EvidenceRelation],
        claims: dict[str, GroundingClaim],
        evidence: dict[str, GroundingEvidence],
    ) -> list[GroundingFinding]:
        findings: list[GroundingFinding] = []
        for relation in relations:
            if relation.claim_id not in claims:
                findings.append(
                    self._finding(
                        GroundingVerificationCode.UNKNOWN_CLAIM,
                        "Evidence relation references an unknown claim",
                    )
                )
            if relation.evidence_id not in evidence:
                findings.append(
                    self._finding(
                        GroundingVerificationCode.UNKNOWN_EVIDENCE,
                        "Evidence relation references an unknown evidence item",
                        claim_id=relation.claim_id,
                    )
                )
            if relation.assessor_id not in self._policy.trusted_assessor_ids:
                findings.append(
                    self._finding(
                        GroundingVerificationCode.UNTRUSTED_ASSESSOR,
                        "Evidence relation was not produced by an approved assessor",
                        claim_id=relation.claim_id,
                    )
                )
        return findings

    def _citation_findings(
        self,
        citation_items: Sequence[GroundingCitation],
        citations: dict[str, GroundingCitation],
        evidence: dict[str, GroundingEvidence],
        claims: dict[str, GroundingClaim],
    ) -> list[GroundingFinding]:
        findings: list[GroundingFinding] = []
        referenced_citations = {
            citation_id for claim in claims.values() for citation_id in claim.citation_ids
        }
        for citation_id in referenced_citations:
            if citation_id not in citations:
                findings.append(
                    self._finding(
                        GroundingVerificationCode.UNKNOWN_CITATION,
                        "Claim references a citation absent from the verified citation set",
                    )
                )
        for citation in citation_items:
            item = evidence.get(citation.evidence_id)
            if item is None:
                findings.append(
                    self._finding(
                        GroundingVerificationCode.UNKNOWN_EVIDENCE,
                        "Citation references an unknown evidence item",
                    )
                )
            elif (
                citation.source_uri != item.source_uri
                or citation.evidence_sha256 != item.content_sha256
            ):
                findings.append(
                    self._finding(
                        GroundingVerificationCode.CITATION_MISMATCH,
                        "Citation provenance differs from the verified evidence source",
                    )
                )
            if citation.citation_id not in referenced_citations:
                findings.append(
                    self._finding(
                        GroundingVerificationCode.UNVERIFIED_CITATION,
                        "Output citation is not bound to an assessed claim",
                    )
                )
        return findings

    def _evaluate_claim(
        self,
        claim: GroundingClaim,
        *,
        request: GroundingRequest,
        normalized_output: str,
        evidence: dict[str, GroundingEvidence],
        citations: dict[str, GroundingCitation],
        valid_review: bool,
    ) -> tuple[list[GroundingFinding], GroundingSignal]:
        findings: list[GroundingFinding] = []
        normalized_claim = self._normalize(claim.text)
        if normalized_claim not in normalized_output:
            findings.append(
                self._finding(
                    GroundingVerificationCode.CLAIM_NOT_IN_OUTPUT,
                    "Assessed claim is absent from the generated output",
                    claim_id=claim.claim_id,
                )
            )

        relations = [
            relation for relation in request.relations if relation.claim_id == claim.claim_id
        ]
        support_relations = [
            relation
            for relation in relations
            if relation.relation == EvidenceRelationKind.SUPPORTS
            and relation.assessor_id in self._policy.trusted_assessor_ids
            and relation.evidence_id in evidence
            and relation.confidence >= self._policy.minimum_support_confidence
            and evidence[relation.evidence_id].has_valid_integrity
            and _TRUST_ORDER[evidence[relation.evidence_id].trust_level]
            >= _TRUST_ORDER[self._policy.minimum_evidence_trust]
        ]
        contradiction_confidence = max(
            (
                relation.confidence
                for relation in relations
                if relation.relation == EvidenceRelationKind.CONTRADICTS
                and relation.assessor_id in self._policy.trusted_assessor_ids
            ),
            default=0.0,
        )
        support_confidence = max(
            (relation.confidence for relation in support_relations),
            default=0.0,
        )
        claim_citations = [
            citations[citation_id] for citation_id in claim.citation_ids if citation_id in citations
        ]
        cited_evidence_ids = {citation.evidence_id for citation in claim_citations}
        support_evidence_ids = {relation.evidence_id for relation in support_relations}
        citations_satisfied = not self._policy.require_citations or (
            bool(claim_citations) and support_evidence_ids.issubset(cited_evidence_ids)
        )

        if contradiction_confidence >= self._policy.contradiction_threshold:
            status = GroundingSupportStatus.CONTRADICTED
            findings.append(
                self._finding(
                    GroundingVerificationCode.CONTRADICTED_CLAIM,
                    "Trusted evidence contradicts the generated claim",
                    claim_id=claim.claim_id,
                )
            )
        elif support_relations and citations_satisfied:
            status = GroundingSupportStatus.SUPPORTED
        else:
            status = GroundingSupportStatus.UNSUPPORTED
            findings.append(
                self._finding(
                    GroundingVerificationCode.UNSUPPORTED_CLAIM,
                    "Generated claim lacks sufficient verified evidence and citations",
                    claim_id=claim.claim_id,
                )
            )

        if contains_absolute_claim(normalized_claim) and status != GroundingSupportStatus.SUPPORTED:
            findings.append(
                self._finding(
                    GroundingVerificationCode.ABSOLUTE_CLAIM_UNSUPPORTED,
                    "Absolute claim lacks sufficient verified support",
                    claim_id=claim.claim_id,
                )
            )
        if (
            claim.model_confidence < self._policy.uncertainty_disclosure_threshold
            and not claim.uncertainty_disclosed
        ):
            findings.append(
                self._finding(
                    GroundingVerificationCode.UNCERTAINTY_NOT_DISCLOSED,
                    "Low-confidence claim does not communicate uncertainty",
                    claim_id=claim.claim_id,
                )
            )

        source_ids = {
            evidence[evidence_id].source_id
            for evidence_id in support_evidence_ids
            if evidence_id in evidence
        }
        if (
            claim.impact_domain in self._policy.high_impact_domains
            and len(source_ids) < self._policy.minimum_high_impact_sources
        ):
            findings.append(
                self._finding(
                    GroundingVerificationCode.HIGH_IMPACT_EVIDENCE_INSUFFICIENT,
                    "High-impact claim lacks enough independent verified sources",
                    claim_id=claim.claim_id,
                )
            )

        review = request.human_review
        human_reviewed = bool(
            valid_review and review is not None and claim.claim_id in review.claim_ids
        )
        return findings, GroundingSignal(
            claim_id=claim.claim_id,
            impact_domain=claim.impact_domain,
            support_status=status,
            model_confidence=claim.model_confidence,
            support_confidence=support_confidence,
            contradiction_confidence=contradiction_confidence,
            evidence_ids=tuple(sorted(support_evidence_ids)),
            source_ids=tuple(sorted(source_ids)),
            citation_ids=tuple(sorted(claim.citation_ids)),
            uncertainty_disclosed=claim.uncertainty_disclosed,
            human_reviewed=human_reviewed,
        )

    def _review_state(
        self,
        request: GroundingRequest,
        now: datetime,
    ) -> tuple[bool, list[GroundingFinding]]:
        high_impact_claim_ids = {
            claim.claim_id
            for claim in request.claims
            if claim.impact_domain in self._policy.high_impact_domains
        }
        if not high_impact_claim_ids:
            return False, []
        review = request.human_review
        if review is None:
            return False, [
                self._finding(
                    GroundingVerificationCode.HUMAN_REVIEW_REQUIRED,
                    "High-impact claims require independent human review",
                )
            ]
        valid = (
            review.request_id == request.request_id
            and review.reviewer_id in self._policy.trusted_reviewer_ids
            and review.assessment_sha256 == request.assessment_sha256
            and high_impact_claim_ids.issubset(review.claim_ids)
            and review.issued_at <= now < review.expires_at
        )
        if not valid:
            return False, [
                self._finding(
                    GroundingVerificationCode.HUMAN_REVIEW_INVALID,
                    "Human review is expired, untrusted, incomplete, or incorrectly bound",
                )
            ]
        if review.decision == HumanReviewDecision.REJECTED:
            return False, [
                self._finding(
                    GroundingVerificationCode.HUMAN_REVIEW_REJECTED,
                    "Independent human reviewer rejected the high-impact claims",
                )
            ]
        return True, []

    def _output_coverage_findings(self, request: GroundingRequest) -> list[GroundingFinding]:
        findings: list[GroundingFinding] = []
        normalized_output = self._normalize(request.output)
        if contains_absolute_claim(normalized_output) and not any(
            contains_absolute_claim(self._normalize(claim.text)) for claim in request.claims
        ):
            findings.append(
                self._finding(
                    GroundingVerificationCode.ABSOLUTE_CLAIM_UNASSESSED,
                    "Output contains an absolute claim absent from the assessed claim set",
                )
            )
        detected_domain = detect_high_risk_domain(normalized_output)
        expected_domain = _DETECTED_DOMAIN.get(detected_domain or "")
        if expected_domain is not None and not any(
            claim.impact_domain == expected_domain for claim in request.claims
        ):
            findings.append(
                self._finding(
                    GroundingVerificationCode.HIGH_IMPACT_DOMAIN_UNCLASSIFIED,
                    "Output contains high-impact advice absent from the classified claim set",
                )
            )
        if contains_citation_candidate(normalized_output) and not request.citations:
            findings.append(
                self._finding(
                    GroundingVerificationCode.UNVERIFIED_CITATION,
                    "Output contains citation-like text without verified citation provenance",
                )
            )
        return findings

    def _result(
        self,
        request: GroundingRequest,
        *,
        findings: Sequence[GroundingFinding],
        signals: Sequence[GroundingSignal] = (),
    ) -> GroundingResult:
        review_only = bool(findings) and all(
            finding.code == GroundingVerificationCode.HUMAN_REVIEW_REQUIRED for finding in findings
        )
        action: Literal[
            GuardAction.ALLOW,
            GuardAction.BLOCK,
            GuardAction.REQUIRE_APPROVAL,
        ] = (
            GuardAction.REQUIRE_APPROVAL
            if review_only
            else GuardAction.BLOCK
            if findings
            else GuardAction.ALLOW
        )
        return GroundingResult(
            request_id=request.request_id,
            action=action,
            findings=tuple(findings),
            signals=tuple(signals),
            approved_output=request.output if action == GuardAction.ALLOW else None,
        )

    def _normalize(self, value: str) -> str:
        normalized = self._normalizer.normalize(value).normalized
        return _WHITESPACE_RE.sub(" ", normalized).strip().casefold()

    @staticmethod
    def _finding(
        code: GroundingVerificationCode,
        message: str,
        *,
        claim_id: str | None = None,
    ) -> GroundingFinding:
        return GroundingFinding(
            code=code,
            severity=Severity.CRITICAL,
            message=message,
            claim_id=claim_id,
        )
