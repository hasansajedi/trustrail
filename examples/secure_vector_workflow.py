"""Authorize and scan vector-store results before model context assembly."""

from trustrail import (
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
)

content = "The approved refund period is thirty days."
chunk = VectorChunk.from_content(
    chunk_id="chunk-1",
    document_id="handbook-v1",
    resource_id="support-handbook",
    content=content,
    source="reviewed-handbook",
    trust_level=TrustLevel.TRUSTED,
    access=VectorAccessPolicy(
        tenant_id="tenant-a",
        owner_id="support-user",
        required_scopes=frozenset({"knowledge:read"}),
    ),
)
embedding = VectorEmbedding.from_chunk(
    chunk,
    embedding_model_id="embed-v1",
    vector=(1.0, 0.0),
)
entry = VectorIndexEntry.from_embedding(
    embedding,
    entry_id="entry-1",
    index_id="support-index",
    namespace="tenant-a",
)
request = VectorRetrievalRequest(
    request_id="request-1",
    principal=VectorPrincipal(
        user_id="support-user",
        tenant_id="tenant-a",
        scopes=frozenset({"knowledge:read"}),
    ),
    index_id="support-index",
    embedding_model_id="embed-v1",
    authorized_document_ids=frozenset({"handbook-v1"}),
    authorized_resource_ids=frozenset({"support-handbook"}),
    query_vector=(1.0, 0.0),
)
hit = VectorRetrievalHit(
    entry_id="entry-1",
    content=content,
    similarity_score=1.0,
    rank=1,
)
workflow = SecureVectorWorkflow(
    VectorRetrievalPolicy(
        allowed_index_ids=frozenset({"support-index"}),
        allowed_embedding_model_ids=frozenset({"embed-v1"}),
    )
)

envelope = workflow.build_context(request, [hit], [entry])
print(envelope.render())
