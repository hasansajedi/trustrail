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
- Reuse outside the collected purpose, permitted residency, retention deadline,
  or training-consent state
- Lifecycle labels lost or weakened across prompts, output, RAG, embeddings,
  caches, traces, logs, memory, datasets, and derived model artifacts
- Source deletion that leaves untracked derivatives, replicas, backups, or
  externally retained copies available

`DataLifecycleManager` integrity-binds lifecycle labels and lineage, denies
incompatible use, cascades deletion planning, tombstones before connector
deletion, and requires bound verification evidence. Correct label issuance,
complete mediation, durable distributed state, external-store guarantees,
backup reconciliation, and model unlearning or retraining remain application,
infrastructure, provider, and governance responsibilities. See
[GenAI data lifecycle and verified deletion](data-lifecycle.md).

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

### MCP Tool Poisoning, Shadowing, and Rug Pulls

- Model-directed instructions hidden in tool descriptions, schema keys or
  values, annotations, and result schemas
- Invisible Unicode channels and confusable names disguising malicious tools
- Duplicate names and cross-tool references shadowing another server's tools
- Open-ended or undocumented schemas creating ambiguous behavior
- Tool metadata changing between discovery, consent, and execution
- Forged or modified discovery and approval snapshots
- Malicious definition content leaking through diffs, findings, or logs

Definition hashes prove equality with reviewed metadata, not server identity,
implementation integrity, or semantic safety. Protect signing keys and snapshot
storage, authenticate the server and reviewer, mediate every execution path, and
combine definition checks with tool authorization, sandboxing, egress controls,
service-side permissions, runtime attestation, monitoring, and sensitive-action
confirmation. See [MCP tool-definition integrity](mcp-tool-integrity.md).

### MCP Message Tampering and Replay

- JSON-RPC request or response payloads changed after TLS termination
- Unsigned downgrade attempts after message signing has been enabled
- An untrusted or substituted public key used to impersonate a peer
- Sender, recipient, user, agent, session, request/response direction, or
  approved tool-definition context rebound across messages
- Expired, stale, future-dated, duplicate, or nonce-modified messages processed
- Concurrent consumers racing a non-atomic replay check
- Invalid signatures poisoning nonce state before a valid message arrives
- Unbounded replay or audit state causing memory exhaustion
- Message payloads or raw identity, session, and nonce values leaking into audit
  events

Signatures provide integrity and attribution relative to a correctly provisioned
key; they do not provide confidentiality, semantic safety, or authorization.
Protect and authenticate keys, keep TLS, derive verification context from local
authenticated state, use a shared atomic replay store across workers, synchronize
clocks, rate-limit verification, and completely mediate requests and responses.
See [MCP message integrity](mcp-message-integrity.md).

### MCP Multi-Server Isolation and Cross-Origin Attacks

- One server declaring, shadowing, or using a confusable version of another
  server's tool name
- Tool descriptions or results directing the model to invoke a different
  server, creating an indirect cross-origin control channel
- A server-caused call omitting or rebinding its initiating server and tool
- A confused deputy changing user, agent, tenant, scope, destination, or session
  context before dispatch
- Shared or mismatched credentials crossing server trust domains
- Unlabeled, mislabeled, tampered, or undeclared tool results flowing to another
  server without an explicit source-tool/destination-tool edge
- Redaction hooks returning unchanged or substituted data, or approvals being
  rebound, forged, expired, or replayed
- Sensitive arguments, results, identities, or credentials leaking through
  denials and audit logs

Isolation policy depends on trustworthy connection identity, provenance labels,
principal context, and complete mediation. Use separately scoped credentials,
preserve causal initiator provenance, authenticate approvals, isolate processes
and model contexts where appropriate, enforce network egress and downstream
authorization, and persist access-controlled audit evidence. See
[MCP server isolation](mcp-server-isolation.md).

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

### Tool Capability Drift and Runtime Substitution (OWASP AISVS C9.3.3 / C9.3.4)

- A tool keeps the same name and argument schema while its executable, service,
  filesystem access, egress, credentials, effects, scopes, or resource limits
  expand
- Discovery, approval, runtime evidence, or execution requests are rebound to a
  different manifest or executor
- Missing, forged, stale, unknown-key, inactive-key, or incomplete enforcement
  evidence is treated as permission to dispatch
- A sandbox policy is wider than the manifest, or narrower than the request,
  while claiming the declared boundary is active
- Output adds undeclared fields, exceeds its size/classification boundary, or
  bypasses validation through replay or a direct connector path

Manifest signatures authenticate declarations; they do not make an executor or
attestor trustworthy and do not configure infrastructure. Independently measure
executor identity, separate publisher/control/runtime keys, completely mediate
dispatch and output release, enforce controls in a hardened sandbox or gateway,
keep failures closed, and use downstream authorization and monitoring. See
[runtime tool capability manifests](runtime-tool-capability-manifests.md).

### Persistent Workflow Tampering and Rollback (OWASP AISVS C9.4.2 / C9.4.4)

- Stored checkpoints changing tenant, agent, session, goal, plan, budgets,
  policy versions, pending actions, approvals, or authorization state
- Execution entries inserted, deleted, duplicated, reordered, moved across
  sessions, or partially restored before a workflow resumes
- A valid old checkpoint or pending approval restored after newer state exists
- Checkpoint and chain heads substituted together without comparison to an
  independently protected monotonic anchor
- Unsigned, forged, unknown-key, inactive-key, expired, stale, or future-dated
  state accepted after restart or failover
- Signing-key, revocation, authorization, clock, or atomic resume-state outages
  turning a verification failure into a resume
- Concurrent workers replaying the same checkpoint or skipping an intermediate
  checkpoint through non-atomic state

Signatures detect changes but do not prevent deletion or provide
confidentiality. Completely mediate persistence and resume, protect signing
keys and trusted anchors outside the agent, recompute content digests from
authoritative storage, use shared atomic replay/revocation state, reauthorize
before effects, and retain append-only audit and transaction evidence. See
[persistent workflow integrity](persistent-workflow-integrity.md).

### Credential Exposure to Agent Context (OWASP AISVS C9.5.4 / MCP01)

- Raw credentials entering prompts, context windows, memory, tool schemas or
  generated arguments, approvals, telemetry, caches, or serialized state
- Debug output, retries, connector exceptions, prepared requests, or malicious
  tool responses reflecting authorization headers or secret material
- Credentials split across streaming chunks or transformed with Base64/hex to
  bypass a per-chunk or plaintext-only detector
- Opaque references rebound across tenants, tools, resources, operations, vault
  versions, policies, or authorized executions
- Capabilities forged, replayed, used after expiry, retained across rotation, or
  consumed concurrently through non-atomic state
- Ambient environment, cloud metadata, SDK, debugger, crash-dump, or direct
  vault access bypassing the broker

Credential capabilities constrain resolution but cannot isolate a compromised
connector or secret provider. Completely mediate credential paths, keep vault
and execution verification outside the agent runtime, use shared atomic state,
disable sensitive HTTP/log/debug capture, restrict network egress, authorize at
the downstream service, continuously test leak canaries, and rotate on suspected
exposure. See [model-blind credential brokering](credential-brokering.md).

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
