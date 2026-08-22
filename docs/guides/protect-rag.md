# Protect RAG pipelines

Retrieved content is untrusted input even when the original user query is safe.
Scan each document before it enters model context.

```python
from trustrail import Document, Guard, TrustLevel

guard = Guard.balanced()
safe_documents = []

for item in search_results:
    document = Document(
        content=item.text,
        source=item.source,
        source_url=item.url,
        trust_level=TrustLevel.UNTRUSTED,
    )
    result = guard.check_document(document)
    if not result.is_blocked:
        safe_documents.append(document)
```

Then build a provenance-labeled data envelope, check it, and validate the final
response:

```python
from trustrail import GuardStage

context_envelope = guard.build_rag_context(safe_documents)
safe_context = guard.protect_rag_context(context_envelope)
response = await model.generate(question, context=safe_context)
safe_response = guard.protect(response, GuardStage.FINAL_OUTPUT)
```

The rendered JSON keeps each document in a `content` field and carries its
application-assigned `document_id`, `source`, `source_url`, `trust_level`, and
integrity digest. JSON encoding prevents retrieved text from closing a delimiter
and masquerading as a neighboring trusted field.

Preserve provenance through the pipeline. Trust level is a risk signal, not a
bypass: trusted sources can be compromised or contain stale malicious content.
Limit retrieved document size and count, and quarantine blocked documents for
review rather than silently indexing them again.
