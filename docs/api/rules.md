# Rules and protocols

Use `BaseRule` to implement an in-process rule. Use the protocols when adapting
external moderation, approval, state, or audit providers.

::: trustrail.rules.base.BaseRule

::: trustrail.rules.base.RuleRegistry

::: trustrail.protocols
    options:
      members: true

## RAG context validation

`RAG-004` requires `GuardStage.RAG_CONTEXT` values to use a valid
`RAGContextEnvelope`. It rejects unlabeled context and detects changes to content,
source, URL, document ID, or trust level after the integrity label was created.

## Persistent memory writes

`MEM-001` classifies persistent `GuardStage.MEMORY_WRITE` values and returns
`REQUIRE_APPROVAL`. Sensitive material is blocked, while ephemeral values continue
through normalization, injection, and sensitive-data scanning without an approval
request.

::: trustrail.rules.memory.PersistentMemoryWriteRule
