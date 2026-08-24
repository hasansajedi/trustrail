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
- Memory write injection

### Insecure Output Handling (OWASP LLM05)
- XSS in rendered output
- Path traversal
- Shell injection

### Excessive Agency (OWASP LLM06)
- Unlimited tool calls
- Runaway agent loops
- Unauthorized operations

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
- Model training security
- Hardware security
- Network-level controls
- Detection of a backdoor or bias already present in correctly hashed, approved bytes
