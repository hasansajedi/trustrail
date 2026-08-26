"""Unit tests for OWASP LLM08 vector and embedding workflow controls."""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from trustrail import (
    GuardAction,
    SecureVectorWorkflow,
    TrustLevel,
    VectorAccessPolicy,
    VectorChunk,
    VectorEmbedding,
    VectorIndexEntry,
    VectorPrincipal,
    VectorRetrievalHit,
    VectorRetrievalPolicy,
    VectorRetrievalRequest,
    VectorVerificationCode,
    VectorVerificationError,
)

CONTENT = "The approved customer handbook describes the standard refund policy."


def _entry(
    *,
    entry_id: str = "entry-1",
    chunk_id: str = "chunk-1",
    document_id: str = "doc-1",
    resource_id: str = "resource-1",
    content: str = CONTENT,
    tenant_id: str = "tenant-a",
    owner_id: str = "user-1",
    allowed_user_ids: frozenset[str] = frozenset({"user-2"}),
    required_scopes: frozenset[str] = frozenset({"knowledge:read"}),
    index_id: str = "support-index-v3",
    embedding_model_id: str = "embed-reviewed-v2",
    vector: tuple[float, ...] = (1.0, 0.0),
) -> VectorIndexEntry:
    chunk = VectorChunk.from_content(
        chunk_id=chunk_id,
        document_id=document_id,
        resource_id=resource_id,
        content=content,
        source="approved-handbook",
        source_url="https://docs.example.test/handbook",
        trust_level=TrustLevel.TRUSTED,
        access=VectorAccessPolicy(
            tenant_id=tenant_id,
            owner_id=owner_id,
            allowed_user_ids=allowed_user_ids,
            required_scopes=required_scopes,
        ),
    )
    embedding = VectorEmbedding.from_chunk(
        chunk,
        embedding_model_id=embedding_model_id,
        vector=vector,
    )
    return VectorIndexEntry.from_embedding(
        embedding,
        entry_id=entry_id,
        index_id=index_id,
        namespace=tenant_id,
    )


def _request(**updates: object) -> VectorRetrievalRequest:
    values: dict[str, object] = {
        "request_id": "request-1",
        "principal": VectorPrincipal(
            user_id="user-1",
            tenant_id="tenant-a",
            scopes=frozenset({"knowledge:read"}),
        ),
        "index_id": "support-index-v3",
        "embedding_model_id": "embed-reviewed-v2",
        "authorized_document_ids": frozenset({"doc-1", "doc-2"}),
        "authorized_resource_ids": frozenset({"resource-1", "resource-2"}),
        "query_vector": (1.0, 0.0),
        "top_k": 5,
    }
    values.update(updates)
    return VectorRetrievalRequest(**values)


def _workflow(**updates: object) -> SecureVectorWorkflow:
    values: dict[str, object] = {
        "allowed_index_ids": frozenset({"support-index-v3"}),
        "allowed_embedding_model_ids": frozenset({"embed-reviewed-v2"}),
    }
    values.update(updates)
    return SecureVectorWorkflow(VectorRetrievalPolicy(**values))


def _hit(
    *,
    entry_id: str = "entry-1",
    content: str = CONTENT,
    score: float = 1.0,
    rank: int = 1,
) -> VectorRetrievalHit:
    return VectorRetrievalHit(
        entry_id=entry_id,
        content=content,
        similarity_score=score,
        rank=rank,
    )


def _codes(result: object) -> set[object]:
    return {finding.code for finding in result.findings}  # type: ignore[attr-defined]


def test_lineage_carries_access_provenance_and_integrity_without_serializing_content():
    entry = _entry()

    chunk = entry.embedding.chunk

    assert chunk.document_id == "doc-1"
    assert chunk.resource_id == "resource-1"
    assert chunk.access.tenant_id == "tenant-a"
    assert chunk.trust_level == TrustLevel.TRUSTED
    assert entry.has_valid_integrity
    serialized = entry.model_dump_json()
    assert CONTENT not in serialized
    assert "[1.0,0.0]" not in serialized


def test_allows_exactly_authorized_integrity_checked_retrieval():
    result = _workflow().verify(_request(), [_hit()], [_entry()])

    assert result.action == GuardAction.ALLOW
    assert len(result.authorized_hits) == 1
    assert result.authorized_hits[0].content == CONTENT
    assert CONTENT not in result.model_dump_json()


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("tenant", VectorVerificationCode.TENANT_MISMATCH),
        ("user", VectorVerificationCode.USER_NOT_AUTHORIZED),
        ("scope", VectorVerificationCode.SCOPE_MISSING),
        ("document", VectorVerificationCode.DOCUMENT_NOT_AUTHORIZED),
        ("resource", VectorVerificationCode.RESOURCE_NOT_AUTHORIZED),
    ],
)
def test_enforces_identity_document_and_resource_authorization(
    mutation: str,
    expected_code: VectorVerificationCode,
):
    request = _request()
    entry = _entry()
    if mutation == "tenant":
        entry = _entry(tenant_id="tenant-b")
    elif mutation == "user":
        entry = _entry(owner_id="different-user", allowed_user_ids=frozenset())
    elif mutation == "scope":
        principal = request.principal.model_copy(update={"scopes": frozenset()})
        request = request.model_copy(update={"principal": principal})
    elif mutation == "document":
        request = request.model_copy(update={"authorized_document_ids": frozenset({"doc-2"})})
    elif mutation == "resource":
        request = request.model_copy(update={"authorized_resource_ids": frozenset({"resource-2"})})

    result = _workflow().verify(request, [_hit()], [entry])

    assert result.is_blocked
    assert expected_code in _codes(result)


def test_rejects_content_changed_after_indexing():
    result = _workflow().verify(
        _request(),
        [_hit(content="Attacker-controlled replacement content")],
        [_entry()],
    )

    assert VectorVerificationCode.CONTENT_INTEGRITY_MISMATCH in _codes(result)


def test_rejects_broken_chunk_to_embedding_to_index_lineage():
    entry = _entry().model_copy(update={"lineage_sha256": "0" * 64})

    result = _workflow().verify(_request(), [_hit()], [entry])

    assert VectorVerificationCode.BROKEN_LINEAGE in _codes(result)


def test_rejects_unknown_store_entry():
    result = _workflow().verify(
        _request(),
        [_hit(entry_id="lookalike-entry")],
        [_entry()],
    )

    assert VectorVerificationCode.UNKNOWN_INDEX_ENTRY in _codes(result)


def test_rejects_cross_tenant_namespace_substitution():
    entry = _entry().model_copy(update={"namespace": "tenant-b"})

    result = _workflow().verify(_request(), [_hit()], [entry])

    assert VectorVerificationCode.TENANT_MISMATCH in _codes(result)
    assert VectorVerificationCode.BROKEN_LINEAGE in _codes(result)


@pytest.mark.parametrize("score", [1.01, -1.01, math.inf, math.nan])
def test_rejects_invalid_similarity_scores_even_after_validation_bypass(score: float):
    hit = _hit().model_copy(update={"similarity_score": score})

    result = _workflow().verify(_request(), [hit], [_entry()])

    assert VectorVerificationCode.INVALID_SIMILARITY_SCORE in _codes(result)


def test_recomputes_similarity_from_trusted_embedding():
    result = _workflow().verify(_request(), [_hit(score=0.95)], [_entry()])

    assert VectorVerificationCode.SIMILARITY_MISMATCH in _codes(result)


def test_rejects_embedding_dimension_substitution():
    entry = _entry(vector=(1.0, 0.0, 0.0))

    result = _workflow().verify(_request(), [_hit()], [entry])

    assert VectorVerificationCode.VECTOR_DIMENSION_MISMATCH in _codes(result)


def test_rejects_rank_reordering():
    result = _workflow().verify(
        _request(),
        [_hit(rank=2)],
        [_entry()],
    )

    assert VectorVerificationCode.RANK_MANIPULATION in _codes(result)


def test_detects_normalization_bypass_duplicate_poisoning():
    content = "Approved policy text"
    hidden_duplicate = "Approved\u200b policy text"
    first = _entry(content=content)
    second = _entry(
        entry_id="entry-2",
        chunk_id="chunk-2",
        document_id="doc-2",
        resource_id="resource-2",
        content=hidden_duplicate,
        vector=(0.8, 0.6),
    )

    result = _workflow().verify(
        _request(),
        [
            _hit(content=content),
            _hit(entry_id="entry-2", content=hidden_duplicate, score=0.8, rank=2),
        ],
        [first, second],
    )

    assert VectorVerificationCode.DUPLICATE_CONTENT in _codes(result)


def test_hit_count_fails_closed_at_request_and_policy_bounds():
    result = _workflow(max_hits=1).verify(
        _request(),
        [_hit(), _hit(entry_id="unknown", rank=2, score=0.5)],
        [_entry()],
    )

    assert VectorVerificationCode.HIT_LIMIT_EXCEEDED in _codes(result)


def test_catalog_size_fails_closed_before_entry_processing():
    result = _workflow(max_catalog_entries=1).verify(
        _request(),
        [_hit()],
        [_entry(), _entry(entry_id="entry-2", chunk_id="chunk-2")],
    )

    assert VectorVerificationCode.CATALOG_LIMIT_EXCEEDED in _codes(result)


def test_require_raises_content_free_error():
    private_content = "private tenant content marker"

    with pytest.raises(VectorVerificationError) as caught:
        _workflow().require(
            _request(),
            [_hit(content=private_content)],
            [_entry()],
        )

    assert private_content not in str(caught.value)
    assert private_content not in caught.value.result.model_dump_json()


def test_non_finite_vectors_are_rejected_at_typed_boundary():
    with pytest.raises(ValidationError, match="finite"):
        _request(query_vector=(math.nan, 0.0))


@pytest.mark.parametrize("vector", [(0.0, 0.0), (math.nan, 0.0)])
def test_validation_bypass_vectors_fail_closed_without_reaching_cosine(
    vector: tuple[float, ...],
):
    request = _request().model_copy(update={"query_vector": vector})

    result = _workflow().verify(request, [_hit()], [_entry()])

    assert VectorVerificationCode.INVALID_EMBEDDING_VECTOR in _codes(result)


def test_validation_bypass_index_vector_fails_closed_without_reaching_cosine():
    embedding = _entry().embedding.model_copy(update={"vector": (0.0, 0.0)})
    entry = _entry().model_copy(update={"embedding": embedding})

    result = _workflow().verify(_request(), [_hit()], [entry])

    assert VectorVerificationCode.INVALID_EMBEDDING_VECTOR in _codes(result)
    assert VectorVerificationCode.BROKEN_LINEAGE in _codes(result)
