# Threat Model

## Threats Addressed

### Prompt Injection (OWASP LLM01)
- Direct injection via user input
- Indirect injection via RAG documents
- Jailbreak attacks
- System prompt hijacking

### Sensitive Information Disclosure (OWASP LLM02:2025)
- PII and payment data across model inputs and outputs
- Credential and private-key leakage
- Verbatim disclosure of application-defined private context
- Accidental content disclosure through findings, audit events, and integration logs

### Supply Chain (OWASP LLM03)
- Unknown, unapproved, untrusted, deprecated, or revoked AI components
- Changed model, dataset, prompt, adapter, plugin, package, and retrieved-artifact bytes
- Supplier, source, kind, or immutable-revision substitution
- Artifact-manifest tampering when its fingerprint is pinned separately
- Injected instructions in third-party API and tool responses

### Data and Model Poisoning (OWASP LLM04)
- Unknown or substituted training, fine-tuning, RAG, memory, metadata, and model sources
- Unauthorized writer, tenant, purpose, kind, trust-label, or version changes
- Content changes after digest capture and broken transformation lineage
- Direct, nested-metadata, invisible-Unicode, and encoded poisoning instructions
- Upstream or application-specific anomaly signals and unavailable detectors
- Persistent-memory injection before human approval

### Improper Output Handling (OWASP LLM05:2025)
- HTML/JavaScript and Markdown rendering injection
- Unsafe URL schemes, host confusion, credentials, and external resources
- SQL, shell, server-side template, LDAP, XML/XPath, and log injection
- Absolute paths, traversal, file wrappers, and symlink-race residual risk
- Ambiguous or oversized structured data, duplicate keys, and type coercion
- Model-selected tools, arguments, generated code, or privileged effects reaching executors

### Excessive Agency (OWASP LLM06)
- Unknown, substituted, over-broad, or open-ended tool functionality
- Arguments outside an exact scalar contract and model-requested scope expansion
- Cross-user or cross-tenant resource access through a confused deputy
- Tool calls outside authenticated, short-lived user intent
- High-impact actions without exact, out-of-band, single-use approval
- Excessive chained actions, retries, parallel calls, or autonomous execution
- Unlimited tool calls and runaway agent loops

### System Prompt Leakage (OWASP LLM07:2025)
- Secrets, credentials, personal data, security configuration, or authorization
  logic embedded in a system prompt
- Direct, indirect, encoded, partial, reconstruction, and cross-boundary prompt
  extraction attempts
- Structured, normalized verbatim, partial, or Base64-encoded prompt fragments in
  generated output
- Accidental prompt retention in serialized validation results, references,
  findings, and exceptions

System prompts remain visible to the model provider and present in application
memory. Semantic paraphrase, novel encodings, multi-turn reconstruction,
provider logging, compromised dependencies, and side channels remain residual
risks. See [system prompt leakage](system-prompt-leakage.md).

### Overreliance (OWASP LLM09)
- Hallucination detection (via grounding verifier)

### Denial of Service (OWASP LLM10)
- Token bomb / large input attacks
- Rate limiting

## SSRF
- Private IP range access
- Cloud metadata service access
- Dangerous URL schemes

## Out of Scope
- Training infrastructure and optimizer security
- Hardware security
- Network-level controls
- Proof that correctly hashed, approved data or model bytes contain no bias,
  factual corruption, semantic poison, or sleeper trigger
