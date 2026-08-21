# RAG security

RAG adds untrusted content, provenance, indexing, and retrieval boundaries. A
document can contain hidden instructions, poisoned facts, exfiltration requests,
or links to internal services.

Use `check_document` before indexing and after retrieval:

```python
from aiRail import Document, Guard, TrustLevel

document = Document(
    content=content,
    source="web-crawl",
    source_url=url,
    trust_level=TrustLevel.UNTRUSTED,
)
result = Guard.strict().check_document(document)
```

## Recommended pipeline

1. Validate source URL and fetch through restricted network egress.
2. Limit content type, byte size, parse depth, and processing time.
3. Scan and quarantine documents before indexing.
4. Preserve immutable source and trust metadata with each chunk.
5. Scan retrieved chunks again before prompt assembly.
6. Assemble retrieved data with `build_rag_context` so provenance and trust
   labels cannot be discarded or confused with instructions.
7. Validate citations and final output before display.

Trust metadata supports policy decisions but must not disable scanning. Re-check
documents when rules change, a source loses trust, or the index is rebuilt.

## Structured context boundary

Do not join retrieved strings directly. `build_rag_context` scans every document,
then places it in a dedicated JSON data channel with its document ID, source URL,
trust level, and an integrity digest. `protect_rag_context` verifies that structure
and scans its content again before it reaches the model:

```python
envelope = guard.build_rag_context(safe_documents)
safe_context = guard.protect_rag_context(envelope)
```

`RAG-004` blocks raw or tampered context at `GuardStage.RAG_CONTEXT` by default.
For a migration period only, applications can set
`GuardConfig(require_rag_context_labels=False)`. This disables the structural
requirement; it does not disable injection or poisoning detection.

The envelope prevents delimiter breakout and accidental loss of application-set
labels. It does not make retrieved instructions trustworthy: assign labels outside
the model, keep tools least-privileged, and continue scanning every segment.
