# Models and enums

All result and configuration objects are typed Pydantic models. They can be
serialized with `model_dump()` or `model_dump_json()`.

::: aiRail.models.core
    options:
      members: true

::: aiRail.models.config
    options:
      members: true

::: aiRail.models.enums
    options:
      members: true

## Structured RAG context

`RAGContextEnvelope.from_documents()` preserves source and trust labels through
prompt assembly. Use `Guard.build_rag_context()` when documents also need to be
scanned before assembly.

::: aiRail.models.rag
    options:
      members: true
