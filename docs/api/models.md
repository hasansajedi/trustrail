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

## Tool authorization

`ToolAuthorizationPolicy` inventories exact, least-privilege capabilities.
`ToolAuthorizationRequest` binds an invocation to trusted identity, intent,
ownership, scope, approval, and execution context. `ToolAuthorizer` returns a
short-lived lease only when every check succeeds.

::: trustrail.models.agency
    options:
      members: true

::: trustrail.agency.ToolAuthorizer
    options:
      members: true

::: trustrail.agency.ToolExecutionBudget
    options:
      members: true

## Context-aware output handling

`OutputHandlingPolicy` defines fail-closed destination constraints.
`OutputHandlingResult` contains only a downstream-safe transformed value; blocked
results and findings do not retain the model output.

::: trustrail.models.output_handling
    options:
      members: true

::: trustrail.output_handling.SafeOutputHandler
    options:
      members: true

::: trustrail.output_handling.ValidatedToolCall
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

## Data and model poisoning

`DataIngestionRecord` binds content to application-assigned provenance,
authorization, integrity, lineage, and anomaly evidence. `DataPoisoningVerifier`
checks that evidence against trusted source policy and emits content-free results.

::: trustrail.models.poisoning
    options:
      members: true

::: trustrail.poisoning.DataPoisoningVerifier
    options:
      members: true
