# Models and enums

All result and configuration objects are typed Pydantic models. They can be
serialized with `model_dump()` or `model_dump_json()`.

::: trustrail.models.core
    options:
      members: true

::: trustrail.models.config
    options:
      members: true

::: trustrail.models.enums
    options:
      members: true

## Structured RAG context

`RAGContextEnvelope.from_documents()` preserves source and trust labels through
prompt assembly. Use `Guard.build_rag_context()` when documents also need to be
scanned before assembly.

::: trustrail.models.rag
    options:
      members: true

## AI supply-chain artifacts

`ArtifactManifest` is a typed inventory of approved models, datasets, prompts,
adapters, plugins, packages, external services, and retrieved artifacts.
`ArtifactVerifier` checks runtime evidence before a component is loaded.

::: trustrail.models.supply_chain
    options:
      members: true

::: trustrail.supply_chain.ArtifactVerifier
    options:
      members: true
