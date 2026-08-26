"""Bypass-oriented security corpus for OWASP LLM08:2025."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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
)

CORPUS_PATH = Path(__file__).parent.parent / "security_corpus" / "vector_embedding_workflows.json"
CASES: list[dict[str, str | None]] = json.loads(CORPUS_PATH.read_text())
CONTENT = "Approved vector knowledge content"


def _entry(
    *,
    entry_id: str = "entry-1",
    chunk_id: str = "chunk-1",
    document_id: str = "doc-1",
    resource_id: str = "resource-1",
    tenant_id: str = "tenant-a",
    content: str = CONTENT,
    vector: tuple[float, ...] = (1.0, 0.0),
) -> VectorIndexEntry:
    chunk = VectorChunk.from_content(
        chunk_id=chunk_id,
        document_id=document_id,
        resource_id=resource_id,
        content=content,
        source="approved-source",
        trust_level=TrustLevel.TRUSTED,
        access=VectorAccessPolicy(
            tenant_id=tenant_id,
            owner_id="user-1",
            required_scopes=frozenset({"vectors:read"}),
        ),
    )
    return VectorIndexEntry.from_embedding(
        VectorEmbedding.from_chunk(
            chunk,
            embedding_model_id="embed-v1",
            vector=vector,
        ),
        entry_id=entry_id,
        index_id="index-v1",
        namespace=tenant_id,
    )


def _request() -> VectorRetrievalRequest:
    return VectorRetrievalRequest(
        request_id="security-request",
        principal=VectorPrincipal(
            user_id="user-1",
            tenant_id="tenant-a",
            scopes=frozenset({"vectors:read"}),
        ),
        index_id="index-v1",
        embedding_model_id="embed-v1",
        authorized_document_ids=frozenset({"doc-1", "doc-2"}),
        authorized_resource_ids=frozenset({"resource-1", "resource-2"}),
        query_vector=(1.0, 0.0),
    )


def _workflow() -> SecureVectorWorkflow:
    return SecureVectorWorkflow(
        VectorRetrievalPolicy(
            allowed_index_ids=frozenset({"index-v1"}),
            allowed_embedding_model_ids=frozenset({"embed-v1"}),
        )
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: str(case["name"]))
def test_vector_embedding_security_corpus(case: dict[str, str | None]):
    request = _request()
    entries = [_entry()]
    hits = [
        VectorRetrievalHit(
            entry_id="entry-1",
            content=CONTENT,
            similarity_score=1.0,
            rank=1,
        )
    ]
    mutation = case["mutation"]
    if mutation == "tenant":
        entries = [_entry(tenant_id="tenant-b")]
    elif mutation == "user-case":
        principal = request.principal.model_copy(update={"user_id": "User-1"})
        request = request.model_copy(update={"principal": principal})
    elif mutation == "scope":
        principal = request.principal.model_copy(update={"scopes": frozenset()})
        request = request.model_copy(update={"principal": principal})
    elif mutation == "document":
        request = request.model_copy(update={"authorized_document_ids": frozenset({"doc-2"})})
    elif mutation == "resource":
        request = request.model_copy(update={"authorized_resource_ids": frozenset({"resource-2"})})
    elif mutation == "content":
        hits[0] = hits[0].model_copy(update={"content": "Replaced after indexing"})
    elif mutation == "score":
        hits[0] = hits[0].model_copy(update={"similarity_score": 0.999})
    elif mutation == "rank-copy":
        hits[0] = hits[0].model_copy(update={"rank": 2})
    elif mutation == "unknown":
        hits[0] = hits[0].model_copy(update={"entry_id": "entry-1.evil"})
    elif mutation == "duplicate":
        duplicate_content = "Approved\u200b vector knowledge content"
        entries.append(
            _entry(
                entry_id="entry-2",
                chunk_id="chunk-2",
                document_id="doc-2",
                resource_id="resource-2",
                content=duplicate_content,
                vector=(0.8, 0.6),
            )
        )
        hits.append(
            VectorRetrievalHit(
                entry_id="entry-2",
                content=duplicate_content,
                similarity_score=0.8,
                rank=2,
            )
        )

    result = _workflow().verify(request, hits, entries)

    assert result.action == GuardAction(str(case["expected_action"]))
    expected_code = case["expected_code"]
    if expected_code is not None:
        assert VectorVerificationCode(expected_code) in {
            finding.code for finding in result.findings
        }
    assert CONTENT not in result.model_dump_json()
