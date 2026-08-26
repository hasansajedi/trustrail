# Vector and embedding security (OWASP LLM08:2025)

Vector stores are authorization and data-integrity boundaries, not trusted text
sources. A high similarity score does not prove that a chunk belongs to the
requesting user, came from an approved document, retained its original content,
or is safe to place in model context.

trustrail's `SecureVectorWorkflow` applies complete mediation after vector-store
retrieval and before RAG context assembly:

1. `VectorChunk` binds content to source, trust, tenant/user access policy,
   document ID, and resource ID.
2. `VectorEmbedding` binds the exact embedding bytes and model identity to that
   chunk.
3. `VectorIndexEntry` binds the embedding lineage to an index and tenant
   namespace. Keep these entries in a trusted catalog outside the model and
   separate from untrusted vector-store result metadata.
4. `VectorRetrievalRequest` carries authenticated identity, scopes, exact
   document/resource grants, the approved index/model, query embedding, and
   retrieval limit.
5. `SecureVectorWorkflow` authorizes every hit, verifies content and lineage,
   recomputes cosine similarity from trusted embeddings, checks ranking, detects
   normalized duplicates, and scans authorized content before building a labeled
   `RAGContextEnvelope`.

## Create lineage-bound index records

Assign authorization and provenance in trusted ingestion code before chunking.
Do not accept these fields from document text, model output, vector-store
metadata, or request parameters without application-side authorization.

```python
from trustrail import (
    TrustLevel,
    VectorAccessPolicy,
    VectorChunk,
    VectorEmbedding,
    VectorIndexEntry,
)

chunk = VectorChunk.from_content(
    chunk_id="chunk-42",
    document_id="handbook-v7",
    resource_id="support-handbook",
    content=chunk_text,
    source="reviewed-handbook",
    source_url="https://docs.example.test/handbook/v7",
    trust_level=TrustLevel.TRUSTED,
    access=VectorAccessPolicy(
        tenant_id="tenant-a",
        owner_id="knowledge-admin",
        allowed_user_ids=frozenset({"support-user"}),
        required_scopes=frozenset({"knowledge:read"}),
    ),
)
embedding = VectorEmbedding.from_chunk(
    chunk,
    embedding_model_id="embed-reviewed-v2",
    vector=embedding_vector,
)
approved_entry = VectorIndexEntry.from_embedding(
    embedding,
    entry_id="entry-42",
    index_id="support-index-v3",
    namespace="tenant-a",
)
```

Run `DataPoisoningVerifier.require()` before this step to authenticate the
source, writer, version, and ingestion purpose. Store the approved entry catalog
in an access-controlled control plane. Content and vector values are excluded
from normal model serialization and representations, but remain in process
memory.

## Authorize retrieval before model context

Build the request from the authenticated session and authoritative document and
resource grants. Query the vector store, translate its results into minimal
`VectorRetrievalHit` objects, then verify them against the trusted catalog:

```python
from trustrail import (
    Guard,
    SecureVectorWorkflow,
    VectorPrincipal,
    VectorRetrievalHit,
    VectorRetrievalPolicy,
    VectorRetrievalRequest,
)

workflow = SecureVectorWorkflow(
    VectorRetrievalPolicy(
        allowed_index_ids=frozenset({"support-index-v3"}),
        allowed_embedding_model_ids=frozenset({"embed-reviewed-v2"}),
        max_hits=10,
        max_catalog_entries=1_000,
        max_embedding_dimensions=3_072,
        similarity_tolerance=1e-5,
        max_identical_content_hits=1,
    )
)
guard = Guard.silent()
request = VectorRetrievalRequest(
    request_id="req-123",
    principal=VectorPrincipal(
        user_id=authenticated_user.id,
        tenant_id=authenticated_user.tenant_id,
        scopes=frozenset(authenticated_user.scopes),
    ),
    index_id="support-index-v3",
    embedding_model_id="embed-reviewed-v2",
    authorized_document_ids=frozenset(authorized_document_ids),
    authorized_resource_ids=frozenset(authorized_resource_ids),
    query_vector=query_embedding,
    top_k=5,
)
hits = [
    VectorRetrievalHit(
        entry_id=item.id,
        content=item.text,
        similarity_score=item.score,
        rank=rank,
    )
    for rank, item in enumerate(vector_results, start=1)
]

context_envelope = workflow.build_context(
    request,
    hits,
    approved_entries,
)
safe_context = guard.protect_rag_context(context_envelope)
```

`build_context()` raises without returning model context when authorization,
integrity, dimensions, score, rank, or duplicate checks fail. Once retrieval is
authorized, it uses content from the trusted catalog and calls the normal RAG
document scanner, so embedded instructions and poisoned text can still block
context construction.

Findings contain stable codes, severity, generic messages, and optional ranks;
they do not retain content, embeddings, identity values, document IDs, resource
IDs, or vector-store metadata.

## Assumptions, limitations, and residual risk

- The principal, scopes, document/resource grants, query vector, and approved
  catalog must come from trusted application state. Model output and vector-store
  metadata are not authorization evidence.
- SHA-256 lineage detects changes relative to the trusted catalog; it is not an
  authenticity proof if an attacker can rewrite both data and catalog. Protect
  the catalog with storage authorization, immutable versions, signed
  attestations where appropriate, and independent audit trails.
- The library verifies logical tenant namespaces but cannot configure physical
  vector-database partitions, encryption, service credentials, network policy,
  backups, or deletion. Enforce those controls at the store.
- Embeddings can leak source information through inversion attacks. Excluding
  vectors from serialization reduces accidental disclosure but does not protect
  process memory or the vector provider. Minimize retention and access, encrypt
  data, and avoid embedding unnecessary sensitive content.
- Similarity verification assumes cosine scores over the exact approved vectors.
  Quantization, provider-specific transformations, or another distance metric
  require a separately reviewed adapter and appropriate tolerance; do not simply
  disable score verification.
- Duplicate detection covers normalized identical content in one result set.
  Semantic duplicates, coordinated poisoning across queries, and gradual ranking
  manipulation require corpus-wide anomaly detection and monitoring.
- Pattern scanning cannot identify every indirect instruction, poisoned fact,
  hidden media channel, knowledge conflict, stale record, or behavior shift.
  Re-scan after extraction and retrieval, evaluate RAG behavior, validate
  citations, and retain human review for consequential decisions.
- Keep content-free immutable retrieval audit logs and alert on repeated denied
  tenants/users, unknown entry IDs, score mismatches, duplicate clusters, and
  abnormal retrieval distributions.
