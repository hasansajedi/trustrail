# Protect RAG pipelines

Retrieved content is untrusted input even when the original user query is safe.
Scan each document before it enters model context.

```python
from trustrail import Document, Guard, GuardContext, GuardStage, TrustLevel

guard = Guard.balanced()
safe_documents = []
request_context = GuardContext(
    request_id=request.id,
    session_id=session.id,
    user_id=authenticated_user.id,
    tenant_id=authenticated_user.tenant_id,
    stage=GuardStage.RAG_DOCUMENT,
    metadata={"trace_id": trace_id},
    tags=["production-rag"],
)

for item in search_results:
    document = Document(
        content=item.text,
        source=item.source,
        source_url=item.url,
        trust_level=TrustLevel.UNTRUSTED,
    )
    result = guard.check_document(document, context=request_context)
    if not result.is_blocked:
        safe_documents.append(document)
```

Then build a provenance-labeled data envelope, check it, and validate the final
response:

```python
from trustrail import GuardStage

context_envelope = guard.build_rag_context(
    safe_documents,
    context=request_context,
)
safe_context = guard.protect_rag_context(
    context_envelope,
    context=request_context,
)
response = await model.generate(question, context=safe_context)
safe_response = guard.protect(response, GuardStage.FINAL_OUTPUT)
```

The rendered JSON keeps each document in a `content` field and carries its
application-assigned `document_id`, `source`, `source_url`, `trust_level`, and
integrity digest. JSON encoding prevents retrieved text from closing a delimiter
and masquerading as a neighboring trusted field.

Populate `GuardContext` identity fields only from authenticated application or
gateway state, never from the query, model, vector result, or document metadata.
`check_document()` keeps those request, session, user, tenant, tag, timestamp,
and correlation values while forcing the scan stage and the document's own trust
level. `build_rag_context()` propagates the same context to every document scan,
and passing it to `protect_rag_context()` correlates the final envelope audit.
Request identity and caller metadata are not serialized into the model-visible
envelope.

Document provenance has fixed collision rules. `Document.id`, `source`,
`source_url`, and `trust_level` are authoritative and cannot be replaced by
caller or document metadata. For other flat metadata keys, caller metadata wins
a collision. The complete original `Document.metadata` remains available to
rules under `context.metadata["document_metadata"]`.

Preserve provenance through the pipeline. Trust level is a risk signal, not a
bypass: trusted sources can be compromised or contain stale malicious content.
Limit retrieved document size and count, and quarantine blocked documents for
review rather than silently indexing them again.

For ingestion-time source, writer, tenant, version, digest, transformation, and
anomaly enforcement, call `DataPoisoningVerifier.require()` before indexing.
Then call `build_rag_context()` after retrieval so the same document is scanned
again at the model-context boundary. See
[Data and model poisoning](../security/data-model-poisoning.md).

When retrieval uses embeddings, do not trust result metadata or similarity
scores from the vector store. Use `SecureVectorWorkflow.build_context()` with an
authenticated request and a separately protected `VectorIndexEntry` catalog; it
authorizes each result, checks full lineage, recomputes similarity, rejects
duplicates, and then invokes the document scanner. See
[Vector and embedding security](../security/vector-embedding-security.md).
