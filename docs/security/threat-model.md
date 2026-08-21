# Threat Model

## Threats Addressed

### Prompt Injection (OWASP LLM01)
- Direct injection via user input
- Indirect injection via RAG documents
- Jailbreak attacks
- System prompt hijacking

### Sensitive Data Exposure (OWASP LLM02, LLM06)
- PII in user input/output (email, phone)
- Secret leakage (API keys, tokens, private keys)
- Payment card data

### Supply Chain (OWASP LLM03)
- RAG document poisoning
- Tool response injection

### Data and Model Poisoning (OWASP LLM04)
- Memory write injection

### Insecure Output Handling (OWASP LLM05)
- XSS in rendered output
- Path traversal
- Shell injection

### Excessive Agency (OWASP LLM08)
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
