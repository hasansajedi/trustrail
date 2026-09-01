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

### Vector and Embedding Weaknesses (OWASP LLM08:2025)
- Cross-user or cross-tenant retrieval caused by missing or attacker-controlled
  metadata filters
- Documents and resources outside the authenticated request's authorization
  grants entering model context
- Loss or mutation of source, trust, access, embedding-model, index, or namespace
  lineage across chunking, embedding, indexing, and retrieval
- Changed retrieved content, unknown index entries, embedding-dimension
  substitution, inflated similarity, rank manipulation, and duplicate poisoning
- Indirect instructions and poisoned content in otherwise authorized chunks
- Accidental disclosure of embedding vectors through results, logs, or exceptions

Physical database isolation, embedding inversion resistance, semantic poisoning,
provider-specific distance calculations, and corpus-wide behavior monitoring
remain application and infrastructure responsibilities. See
[vector and embedding security](vector-embedding-security.md).

### Misinformation and Unsafe Overreliance (OWASP LLM09:2025)
- Unsupported or contradicted generated claims reaching users or automation
- Fabricated, unknown, or provenance-mismatched citations
- Evidence changed after assessment or supplied below the configured trust level
- Low-confidence output presented without uncertainty disclosure
- Absolute or high-impact claims omitted from the assessed claim inventory
- Medical, legal, financial, security, safety, employment, or other high-impact
  output released without independent sources and bound human approval
- Human approval replayed across requests or used after expiration

Evidence digests establish integrity relative to captured content, not publisher
authenticity or truth. Sources and automated assessors can be stale, biased,
dependent, compromised, or wrong; claim extraction and keyword rules can miss
semantic and multilingual statements; human reviewers can make mistakes or
suffer automation bias. See
[misinformation and unsafe overreliance](misinformation-overreliance.md).

### Unbounded Consumption (OWASP LLM10:2025)
- Oversized or multibyte input and provider output beyond requested limits
- Token flooding, recursive expansion, deep nesting, and compressed-data bombs
- Concurrent operations, retries, tool loops, and sessions exceeding hard budgets
- Slow cumulative exhaustion across requests or attacker-rotated session IDs
- Reservation replay and abandoned operations retaining concurrency capacity
- Resource-state exhaustion and accidental content retention in audit findings

The built-in atomic ledger is process-local, token counts depend on trusted exact
measurement, and leases do not constrain operating-system or remote-provider
resources. Distributed quotas, billing controls, provider cancellation, identity
abuse prevention, parser sandboxes, and infrastructure isolation remain required.
See [bounded resource consumption](resource-consumption.md).

### Agent Goal Hijack (OWASP ASI01:2026)

- Untrusted user, RAG, memory, tool, or intermediate planning content replacing
  the authorized objective
- Small goal changes accumulating without explicit review
- Goal-hijacking instructions split across multiple steps or hidden with common
  text encodings and invisible Unicode
- Plan steps dropping constraints or rebinding to stale manifests
- Cross-owner, cross-tenant, cross-session, or cross-execution goal reuse
- Unknown delegates acting before an authorized delegation step
- Material objective, constraint, action, or delegate changes without an exact,
  authenticated, single-use approval
- Sensitive objective or mutation content leaking through results and audit logs

Manifest digests establish integrity, not authenticity or semantic correctness.
Application-owned state, complete mediation, narrow actions, downstream tool
authorization, durable shared execution state, independent review, and behavioral
monitoring remain required. See [agent goal integrity](agent-goal-integrity.md).

### Tool Misuse and Exploitation (OWASP ASI02:2026)

- Schema-valid arguments that change the intended recipient, value, purpose, or
  affected resource
- Individually authorized calls combined into a dangerous or undeclared sequence
- Retrieved secrets or one tool's output forwarded into an unrelated tool
- Tool adapters reporting success while producing undeclared effects or touching
  additional resources and destinations
- Missing, forged, replayed, or cross-intent provenance for tool-derived values
- Unknown or partially failed outcomes followed by continued autonomous actions
- Rollback hooks failing or being treated as proof that irreversible effects were
  undone

Typed policies cannot establish whether application-supplied facts or reports are
true. Use authoritative identity and state, complete mediation, authenticated
adapters, shared atomic execution history, conditional writes, idempotency,
service-side authorization, value and egress limits, and human review for
high-impact operations. See [semantic tool authorization](tool-misuse.md).

### Identity and Privilege Abuse (OWASP ASI03:2026)

- Agents impersonating a user, service, peer agent, or sub-agent by changing an
  untrusted identity field
- User or service credentials forwarded through an agent chain instead of
  being exchanged for narrow delegated authority
- A confused deputy reusing valid authority for another audience, purpose,
  tenant, or operation
- Child agents expanding scope, lifetime, audience, or maximum delegation depth
- Expired, not-yet-valid, revoked, tampered, unauthenticated, or replayed
  capability and elevation records
- High-impact work executed without independent step-up authentication or
  just-in-time privilege activation
- Revocation-provider failure, concurrency races, or a direct tool path turning
  a deny into an allow

Capability digests establish field integrity, not issuer authenticity. Use
authenticated workload identities, protected or signed issuance, proof of
possession, complete mediation, short lifetimes, shared atomic revocation/replay
state, downstream service authorization, and independent approval for
high-impact operations. See
[delegated agent identity](delegated-agent-identity.md).

### Unexpected Code Execution (OWASP ASI05:2026)

- Generated code, scripts, commands, templates, or package selections reaching
  an interpreter without an explicit execution request
- Shell expansion, dynamic evaluation, interpreter introspection, dangerous
  imports, native extensions, or process-launch APIs bypassing review
- Runtime or package substitution after source inspection
- Filesystem traversal, host mounts, symlink escape, network egress, metadata
  access, or ambient credentials turning sandbox work into host compromise
- Missing, forged, expired, rebound, or replayed sandbox attestations
- CPU, memory, process, thread, file, output, or wall-time exhaustion
- Forged success, resource, output, or cleanup reports releasing unsafe results
- Failed cleanup leaving processes, files, network access, or credentials active

Static admission checks cannot prove arbitrary code safe, and trustrail does not
provide OS isolation. Use a hardened external sandbox with authenticated
evidence, immutable runtimes, deny-by-default privileges, hard infrastructure
limits, complete mediation, verified teardown, sandbox-escape testing, and
destination-specific output handling. See
[isolated agent code execution](code-execution-isolation.md).

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
