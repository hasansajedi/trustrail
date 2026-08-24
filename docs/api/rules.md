# Rules and protocols

Use `BaseRule` to implement an in-process rule. Use the protocols when adapting
external moderation, approval, state, or audit providers.

::: trustrail.rules.base.BaseRule

::: trustrail.rules.base.RuleRegistry

::: trustrail.protocols
    options:
      members: true

## Model output safety

`OS-001` through `OS-013` cover HTML, paths, shell syntax, URLs, Markdown
images, dangerous code, SQL, templates, logs, LDAP, XML/XPath, and file-wrapper
injection. They scan the complete guard-bounded value, emit content-free
findings, and map to OWASP `LLM05:2025`.

Detection rules are an early warning layer. Use `SafeOutputHandler` to enforce
the actual browser, database, process, filesystem, structured-data, or tool
boundary.

## RAG context validation

`RAG-004` requires `GuardStage.RAG_CONTEXT` values to use a valid
`RAGContextEnvelope`. It rejects unlabeled context and detects changes to content,
source, URL, document ID, or trust level after the integrity label was created.
`DP-001` blocks common poisoned-context markers before documents are assembled.
Both rules map to OWASP LLM04:2025.

`PI-007` recursively scans nested metadata values, including normalized and
base64-decoded variants. It fails closed when metadata exceeds configured depth
or node bounds and does not copy attacker-controlled keys or values into findings.

## Persistent memory writes

`MEM-001` classifies persistent `GuardStage.MEMORY_WRITE` values and returns
`REQUIRE_APPROVAL`. Sensitive material is blocked, while ephemeral values continue
through normalization, injection, and sensitive-data scanning without an approval
request.

::: trustrail.rules.memory.PersistentMemoryWriteRule
