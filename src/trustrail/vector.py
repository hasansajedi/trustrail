"""Fail-closed verification for vector retrieval and embedding workflows."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from collections.abc import Sequence
from typing import TYPE_CHECKING

from trustrail.exceptions import VectorVerificationError
from trustrail.models.enums import GuardAction, Severity
from trustrail.models.rag import RAGContextEnvelope
from trustrail.models.vector import (
    AuthorizedVectorHit,
    VectorIndexEntry,
    VectorRetrievalHit,
    VectorRetrievalPolicy,
    VectorRetrievalRequest,
    VectorVerificationCode,
    VectorVerificationFinding,
    VectorVerificationResult,
)

if TYPE_CHECKING:
    from trustrail.guard import Guard


class SecureVectorWorkflow:
    """Authorize and integrity-check retrieval before model context assembly."""

    def __init__(self, policy: VectorRetrievalPolicy) -> None:
        self._policy = policy.model_copy(deep=True)

    @property
    def policy(self) -> VectorRetrievalPolicy:
        """Return a defensive copy of the active retrieval policy."""
        return self._policy.model_copy(deep=True)

    def verify(
        self,
        request: VectorRetrievalRequest,
        hits: Sequence[VectorRetrievalHit],
        approved_entries: Sequence[VectorIndexEntry],
    ) -> VectorVerificationResult:
        """Verify identity, access, lineage, content, ranks, and similarity."""
        findings: list[VectorVerificationFinding] = []
        findings.extend(self._request_findings(request, hits))
        if len(approved_entries) > self._policy.max_catalog_entries:
            findings.append(
                self._finding(
                    VectorVerificationCode.CATALOG_LIMIT_EXCEEDED,
                    "Trusted vector catalog exceeds the configured verification limit",
                )
            )
        if findings:
            return VectorVerificationResult(
                request_id=request.request_id,
                action=GuardAction.BLOCK,
                findings=tuple(findings),
            )

        entry_counts = Counter(entry.entry_id for entry in approved_entries)
        if any(count > 1 for count in entry_counts.values()):
            findings.append(
                self._finding(
                    VectorVerificationCode.CATALOG_DUPLICATE,
                    "Trusted vector catalog contains duplicate entry identifiers",
                )
            )
        catalog = {entry.entry_id: entry for entry in approved_entries}

        authorized: list[AuthorizedVectorHit] = []
        normalized_content_counts: Counter[str] = Counter()
        previous_score: float | None = None
        seen_ranks: set[int] = set()
        for position, hit in enumerate(hits, start=1):
            if self._policy.require_sequential_ranks and (
                hit.rank != position or hit.rank in seen_ranks
            ):
                findings.append(
                    self._finding(
                        VectorVerificationCode.RANK_MANIPULATION,
                        "Retrieved ranks are duplicated, missing, or out of order",
                        rank=hit.rank,
                    )
                )
            seen_ranks.add(hit.rank)

            if previous_score is not None and hit.similarity_score > previous_score:
                findings.append(
                    self._finding(
                        VectorVerificationCode.RANK_MANIPULATION,
                        "Similarity scores are inconsistent with retrieval order",
                        rank=hit.rank,
                    )
                )
            previous_score = hit.similarity_score

            entry = catalog.get(hit.entry_id)
            if entry is None:
                findings.append(
                    self._finding(
                        VectorVerificationCode.UNKNOWN_INDEX_ENTRY,
                        "Retrieved entry is absent from the trusted vector catalog",
                        rank=hit.rank,
                    )
                )
                continue

            entry_findings = self._entry_findings(request, hit, entry)
            findings.extend(entry_findings)
            chunk = entry.embedding.chunk
            normalized_content_counts[chunk.normalized_content_sha256] += 1
            if not entry_findings:
                authorized.append(
                    AuthorizedVectorHit(
                        entry_id=entry.entry_id,
                        chunk_id=chunk.chunk_id,
                        document_id=chunk.document_id,
                        resource_id=chunk.resource_id,
                        content=chunk.content,
                        source=chunk.source,
                        source_url=chunk.source_url,
                        trust_level=chunk.trust_level,
                        similarity_score=hit.similarity_score,
                        rank=hit.rank,
                    )
                )

        for count in normalized_content_counts.values():
            if count > self._policy.max_identical_content_hits:
                findings.append(
                    self._finding(
                        VectorVerificationCode.DUPLICATE_CONTENT,
                        "Retrieval contains repeated normalized content that can bias ranking",
                    )
                )
                break

        if findings:
            return VectorVerificationResult(
                request_id=request.request_id,
                action=GuardAction.BLOCK,
                findings=tuple(findings),
            )
        return VectorVerificationResult(
            request_id=request.request_id,
            action=GuardAction.ALLOW,
            authorized_hits=tuple(authorized),
        )

    def require(
        self,
        request: VectorRetrievalRequest,
        hits: Sequence[VectorRetrievalHit],
        approved_entries: Sequence[VectorIndexEntry],
    ) -> tuple[AuthorizedVectorHit, ...]:
        """Return authorized hits or raise before content reaches the model."""
        result = self.verify(request, hits, approved_entries)
        if result.is_blocked:
            raise VectorVerificationError(result=result)
        return result.authorized_hits

    def build_context(
        self,
        request: VectorRetrievalRequest,
        hits: Sequence[VectorRetrievalHit],
        approved_entries: Sequence[VectorIndexEntry],
        *,
        guard: Guard | None = None,
    ) -> RAGContextEnvelope:
        """Authorize retrieval, scan every chunk, and build labeled model context."""
        if guard is None:
            from trustrail.guard import Guard

            guard = Guard.silent()
        authorized = self.require(request, hits, approved_entries)
        return guard.build_rag_context([hit.to_document() for hit in authorized])

    def _request_findings(
        self,
        request: VectorRetrievalRequest,
        hits: Sequence[VectorRetrievalHit],
    ) -> list[VectorVerificationFinding]:
        findings: list[VectorVerificationFinding] = []
        if request.index_id not in self._policy.allowed_index_ids:
            findings.append(
                self._finding(
                    VectorVerificationCode.INDEX_NOT_ALLOWED,
                    "Requested vector index is not allowlisted",
                )
            )
        if request.embedding_model_id not in self._policy.allowed_embedding_model_ids:
            findings.append(
                self._finding(
                    VectorVerificationCode.EMBEDDING_MODEL_NOT_ALLOWED,
                    "Requested embedding model is not allowlisted",
                )
            )
        if len(request.query_vector) > self._policy.max_embedding_dimensions:
            findings.append(
                self._finding(
                    VectorVerificationCode.VECTOR_DIMENSION_MISMATCH,
                    "Query embedding exceeds the configured dimension limit",
                )
            )
        if not all(math.isfinite(value) for value in request.query_vector) or not any(
            value != 0.0 for value in request.query_vector
        ):
            findings.append(
                self._finding(
                    VectorVerificationCode.INVALID_EMBEDDING_VECTOR,
                    "Query embedding contains invalid values or has zero norm",
                )
            )
        if len(hits) > min(request.top_k, self._policy.max_hits):
            findings.append(
                self._finding(
                    VectorVerificationCode.HIT_LIMIT_EXCEEDED,
                    "Vector store returned more hits than the authorized retrieval limit",
                )
            )
        return findings

    def _entry_findings(
        self,
        request: VectorRetrievalRequest,
        hit: VectorRetrievalHit,
        entry: VectorIndexEntry,
    ) -> list[VectorVerificationFinding]:
        findings: list[VectorVerificationFinding] = []
        chunk = entry.embedding.chunk
        access = chunk.access
        if not entry.has_valid_integrity:
            findings.append(
                self._finding(
                    VectorVerificationCode.BROKEN_LINEAGE,
                    "Chunk, embedding, or index lineage verification failed",
                    rank=hit.rank,
                )
            )
        if entry.index_id != request.index_id:
            findings.append(
                self._finding(
                    VectorVerificationCode.INDEX_NOT_ALLOWED,
                    "Retrieved entry belongs to a different vector index",
                    rank=hit.rank,
                )
            )
        if entry.embedding.embedding_model_id != request.embedding_model_id:
            findings.append(
                self._finding(
                    VectorVerificationCode.EMBEDDING_MODEL_NOT_ALLOWED,
                    "Retrieved entry uses a different embedding model",
                    rank=hit.rank,
                )
            )
        if access.tenant_id != request.principal.tenant_id:
            findings.append(
                self._finding(
                    VectorVerificationCode.TENANT_MISMATCH,
                    "Retrieved resource belongs to a different tenant",
                    rank=hit.rank,
                )
            )
        if entry.namespace != access.tenant_id:
            findings.append(
                self._finding(
                    VectorVerificationCode.TENANT_MISMATCH,
                    "Vector namespace is not bound to the resource tenant",
                    rank=hit.rank,
                )
            )
        user_allowed = (
            access.allow_tenant_users
            or request.principal.user_id == access.owner_id
            or request.principal.user_id in access.allowed_user_ids
        )
        if not user_allowed:
            findings.append(
                self._finding(
                    VectorVerificationCode.USER_NOT_AUTHORIZED,
                    "Authenticated user is not authorized for the retrieved resource",
                    rank=hit.rank,
                )
            )
        if not access.required_scopes.issubset(request.principal.scopes):
            findings.append(
                self._finding(
                    VectorVerificationCode.SCOPE_MISSING,
                    "Authenticated principal lacks a required retrieval scope",
                    rank=hit.rank,
                )
            )
        if chunk.document_id not in request.authorized_document_ids:
            findings.append(
                self._finding(
                    VectorVerificationCode.DOCUMENT_NOT_AUTHORIZED,
                    "Retrieved document is outside the authorized request scope",
                    rank=hit.rank,
                )
            )
        if chunk.resource_id not in request.authorized_resource_ids:
            findings.append(
                self._finding(
                    VectorVerificationCode.RESOURCE_NOT_AUTHORIZED,
                    "Retrieved resource is outside the authorized request scope",
                    rank=hit.rank,
                )
            )
        if chunk.content_sha256 != self._content_sha256(hit.content):
            findings.append(
                self._finding(
                    VectorVerificationCode.CONTENT_INTEGRITY_MISMATCH,
                    "Retrieved content differs from the approved indexed chunk",
                    rank=hit.rank,
                )
            )

        vector = entry.embedding.vector
        if not all(math.isfinite(value) for value in vector) or not any(
            value != 0.0 for value in vector
        ):
            findings.append(
                self._finding(
                    VectorVerificationCode.INVALID_EMBEDDING_VECTOR,
                    "Indexed embedding contains invalid values or has zero norm",
                    rank=hit.rank,
                )
            )
        elif (
            len(vector) != len(request.query_vector)
            or len(vector) > self._policy.max_embedding_dimensions
        ):
            findings.append(
                self._finding(
                    VectorVerificationCode.VECTOR_DIMENSION_MISMATCH,
                    "Query and indexed embedding dimensions do not match policy",
                    rank=hit.rank,
                )
            )
        elif not math.isfinite(hit.similarity_score) or not -1.0 <= hit.similarity_score <= 1.0:
            findings.append(
                self._finding(
                    VectorVerificationCode.INVALID_SIMILARITY_SCORE,
                    "Vector store returned an invalid cosine similarity score",
                    rank=hit.rank,
                )
            )
        else:
            expected = self._cosine_similarity(request.query_vector, vector)
            if abs(hit.similarity_score - expected) > self._policy.similarity_tolerance:
                findings.append(
                    self._finding(
                        VectorVerificationCode.SIMILARITY_MISMATCH,
                        "Reported similarity differs from the trusted embedding calculation",
                        rank=hit.rank,
                    )
                )
        return findings

    @staticmethod
    def _content_sha256(content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()

    @staticmethod
    def _cosine_similarity(left: tuple[float, ...], right: tuple[float, ...]) -> float:
        numerator = sum(a * b for a, b in zip(left, right, strict=True))
        left_norm = math.sqrt(sum(value * value for value in left))
        right_norm = math.sqrt(sum(value * value for value in right))
        return numerator / (left_norm * right_norm)

    @staticmethod
    def _finding(
        code: VectorVerificationCode,
        message: str,
        *,
        rank: int | None = None,
    ) -> VectorVerificationFinding:
        return VectorVerificationFinding(
            code=code,
            severity=Severity.CRITICAL,
            message=message,
            rank=rank,
        )
