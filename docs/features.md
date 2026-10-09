# Feature and control catalog

This page inventories the implemented public security capabilities in the
`trustrail` package. It is a source-backed catalog: the API column names the
enforcement entry point users call, while the linked guide describes trust
assumptions, configuration, failure behavior, and residual risk.

Most typed request, policy, result, finding, and evidence models are exported
directly from `trustrail`. The [API reference](api/index.md) documents their
fields.

## Core guard and content boundaries

| Capability | Primary public API | What is enforced | Guide / example |
| --- | --- | --- | --- |
| Guard pipeline | `Guard`, `GuardContext`, `GuardStage`, `GuardResult` | Ordered normalization, rule evaluation, risk scoring, redaction, block/approval decisions, and sync/async execution | [Quick start](quickstart.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/basic_input.py) |
| Prompt injection | `Guard` with prompt-injection policies and rules | Direct, indirect, jailbreak, encoded, Unicode-control, metadata, boundary, and extraction patterns | [Guide](security/prompt-injection.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/prompt_boundaries.py) |
| Sensitive data | `Guard`, `SensitiveDataMode`, `ProtectedData` | PII, protected attributes, secrets, API keys, payment data, allow/deny/redact behavior | [Guide](security/sensitive-data.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/configuration_and_audit.py) |
| Context-aware output | `SafeOutputHandler`, `OutputHandlingPolicy`, `ValidatedToolCall` | Fail-closed HTML, SQL, shell, path, URL, JSON, XML, template, log, Markdown, and typed tool boundaries | [Guide](security/output-handling.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/output_handling.py) |
| URL and SSRF checks | URL rules plus `SafeOutputHandler` | Dangerous schemes, private/link-local/metadata destinations, credentials, redirects, and destination policy | [Tool guide](guides/protect-tools.md) |
| Conversation protection | `Guard.protect_messages()`, `Message` | Atomic role-aware scanning while preserving message order and tool-call relationships | [Quick start](quickstart.md#protecting-conversations) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/conversation.py) |
| Streaming | `StreamScanner`, `StreamResult` | Cross-chunk detection with bounded holdback and explicit safe chunks | [Guide](guides/protect-streaming.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/streaming.py) |
| External safety providers | `ProviderRegistration`, `AsyncRuleRegistration` and provider protocols | Awaited moderation, DLP, prompt-injection, and grounding checks with deadlines, concurrency bounds, and fail modes | [Guide](integrations/external-safety-providers.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/async_providers.py) |
| Custom rules and policies | `BaseRule`, `BaseAsyncRule`, `GuardPolicy`, provider protocols | Application rules with typed findings, phases, categories, and configuration | [Guide](custom-rules.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/custom_policy.py) |

## RAG, data, memory, and model governance

| Capability | Primary public API | What is enforced | Guide / example |
| --- | --- | --- | --- |
| RAG provenance | `RAGContextEnvelope`, `Guard.build_rag_context()` | Document scanning, immutable source/trust labels, metadata bounds, and context integrity | [Guide](security/rag-security.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/rag_example.py) |
| Secure vector retrieval | `SecureVectorWorkflow` | Tenant/user/resource access, authoritative index lineage, similarity integrity, duplicate limits, and safe context assembly | [Guide](security/vector-embedding-security.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/secure_vector_workflow.py) |
| Data/model poisoning | `DataPoisoningVerifier` | Trusted source, writer, tenant, version, digest, lineage, transformation, and anomaly evidence before ingestion | [Guide](security/data-model-poisoning.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/data_poisoning.py) |
| AI supply chain | `ArtifactVerifier` | Approved provenance, immutable revision, digest, component kind, and runtime observation before load | [Guide](security/supply-chain.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/supply_chain.py) |
| Training-data governance | `TrainingDataGovernanceVerifier` | Feature minimization, sensitive handling, label writer/approver integrity, transformation pinning, quality evidence, and aggregate bias thresholds | [Guide](security/training-data-governance.md) |
| Data labels | `DataLabelSigner`, `DataLabelVerifier`, `DataLabelPropagator`, `DataLabelGuard` | Signed classification, handling requirements, lineage, join semantics, destination checks, and downgrade prevention | [Guide](security/data-label-propagation.md) |
| Data lifecycle | `DataLifecycleManager` | Registration, derivation, purpose/residency/retention/consent checks, tombstone-first deletion, and connector verification | [Guide](security/data-lifecycle.md) |
| Persistent memory | `MemoryTaintManager` plus memory guard policy | Approval before writes, exact-byte commit, provenance, dependencies, taint, retrieval revalidation, invalidation, and rebuild | [Guide](security/memory-security.md) · [examples](https://github.com/hasansajedi/trustrail/tree/main/examples) (`persistent_memory.py`, `memory_taint.py`) |
| Multi-tenant AI state | `TenantContextSigner`, `TenantStateKeyBuilder`, `TenantIsolationGuard` | Signed tenant context and isolated cache, memory, adapter, checkpoint, index, rate-limit, and batch state | [Guide](security/multi-tenant-isolation.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/tenant_isolation.py) |
| System prompts | `SystemPromptValidator`, `SystemPromptLeakageDetector` | Classified prompt construction, exclusion of authorization/secrets, extraction detection, and bounded fragment comparison | [Guide](security/system-prompt-leakage.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/system_prompt_security.py) |
| Evidence grounding | `EvidenceGroundingVerifier` | Claim/citation/evidence binding, provenance, support relation, uncertainty, freshness, high-impact review, and safe provenance signals | [Guide](security/misinformation-overreliance.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/evidence_grounding.py) |

## Agent identity, authorization, and execution

| Capability | Primary public API | What is enforced | Guide / example |
| --- | --- | --- | --- |
| Agent session budgets | `AgentSession` | Step count, tool-call count, recursion depth, and duration bounds | [Agent guide](guides/protect-agents.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/agent.py) |
| Least-privilege tool authorization | `ToolAuthorizer`, `ToolExecutionBudget` | Identity, subject, tenant, intent, ownership, scopes, arguments, approval, leases, and execution budgets | [Guide](security/excessive-agency.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/tool_authorization.py) |
| Semantic tool authorization | `ToolAuthorizer` with semantic policy | Trusted argument bindings, effects, resource transitions, sequence rules, data flows, compensation, and postconditions | [Guide](security/tool-misuse.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/semantic_tool_authorization.py) |
| Delegated identity | `DelegatedIdentityAuthorizer` | Human/service/agent lineage, scope and audience narrowing, purpose, tenant, lifetime, depth, revocation, and JIT grants | [Guide](security/delegated-agent-identity.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/delegated_identity.py) |
| Goal integrity | `GoalIntegrityGuard`, `GoalExecutionState` | Authorized objective, constraints, owner, plan actions, delegates, material mutations, and exact approvals | [Guide](security/agent-goal-integrity.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/goal_integrity.py) |
| High-impact approvals | `HighImpactApprovalGate` | Complete canonical previews, trusted action classifications, exact plan binding, fatigue limits, reviewer policy, expiry, and nonce replay | [Guide](security/high-impact-approvals.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/high_impact_approval.py) |
| Step-up/JIT privileges | `PrivilegedAccessManager` | Authenticated identity/risk snapshots, backend authorization, step-up evidence, approval, exact operation grants, expiry, consumption, and revocation | [Guide](security/privileged-ai-access.md) |
| Model-blind credentials | `CredentialBroker`, `CredentialBoundaryGuard` | Opaque references, execution-bound single-use capabilities, vault versioning, rotation/revocation, and leak checks on model-visible surfaces | [Guide](security/credential-brokering.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/credential_brokering.py) |
| Runtime tool manifests | `ToolManifestSigner`, `ToolCapabilityEnforcer`, `ToolRuntimeEvidenceSigner` | Signed capability ceilings, exact executor/resource/egress/filesystem limits, approval binding, and verified runtime output | [Guide](security/runtime-tool-capability-manifests.md) |
| Isolated code execution | `CodeExecutionAuthorizer` | Source/argv digest, attested sandbox, language/runtime/package policy, filesystem/network/environment/resource limits, cleanup, and output verification | [Guide](security/code-execution-isolation.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/isolated_code_execution.py) |
| Inter-agent communication | `InterAgentMessageSigner`, `InterAgentMessageVerifier` | Signed payload, sender/recipient/delegation, tenant/session/goal/task/purpose, sequence, fan-out, transformation, freshness, and replay | [Guide](security/inter-agent-communication.md) |
| Rogue-agent runtime | `RuntimeInvariantSigner`, `RogueAgentRuntimeMonitor` | Signed capability ceilings and runtime invariants, event admission, containment hooks, quarantine, recovery authorization, and content-free evidence | [Guide](security/rogue-agent-runtime.md) |
| Failure containment | `FailureContainmentManager` | Tenant-scoped circuits, authenticated dependency outcomes, retry/side-effect limits, trusted fallbacks, degraded mode, and recovery | [Guide](security/cascading-failure-containment.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/cascading_failures.py) |
| Persistent workflow integrity | `WorkflowCheckpointSigner`, `PersistentWorkflowVerifier` | Signed checkpoints, append-only execution chains, budgets, policy versions, pending actions/approvals, rollback/tamper detection, and single-use resume | [Guide](security/persistent-workflow-integrity.md) |
| Resource consumption | `ResourceBudgetManager`, `BoundedDecompressor` | Token, request, concurrency, retry, tool-loop, session, duration, nesting, input-size, and decompression bounds | [Guide](security/resource-consumption.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/resource_budget.py) |

## MCP security

| Capability | Primary public API | What is enforced | Guide / example |
| --- | --- | --- | --- |
| Tool-definition integrity | `MCPToolDefinitionGuard` | Full schema scanning, canonical digest, confusable/shadow tool detection, discovery pinning, and mutation consent | [Guide](security/mcp-tool-integrity.md) |
| Secure server onboarding | `MCPServerOnboardingGuard` | Publisher/source/version/command/transport/capability policy, explicit consent, sandbox evidence, secret references, and short-lived permits | [Guide](security/mcp-server-onboarding.md) |
| OAuth resource authorization | `MCPOAuthResourceServer`, `MCPOAuthDownstreamBroker` | Pinned signed token profile, exact issuer/audience/resource/principal/request claims, replay, filtered discovery, tool/resource checks, and non-passthrough credentials | [Guide](security/mcp-oauth.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/mcp_oauth.py) |
| Message integrity | `MCPMessageSigner`, `MCPMessageVerifier` | Signed JSON-RPC payload, peer/user/agent/session/direction/tool-definition binding, freshness, and replay prevention | [Guide](security/mcp-message-integrity.md) |
| Multi-server isolation | `MCPServerIsolationGateway` | Server trust domains, namespaces, credentials, principals, tool ownership, labeled result integrity, explicit data-flow edges, redaction, and approval | [Guide](security/mcp-server-isolation.md) |

## Operations, testing, and integrations

| Capability | Primary public API | What is enforced or provided | Guide / example |
| --- | --- | --- | --- |
| Audit sinks | `AuditSink`, `LoggingAuditSink`, `MemoryAuditSink`, control-specific sinks | Structured decision evidence with content-minimizing event models | [Observability](observability.md) |
| OpenTelemetry | `OtelAuditSink` | Audit-event export to configured telemetry infrastructure | [Observability](observability.md) |
| Local/distributed state | `MemoryStateBackend`, `RedisStateBackend`, `FixedWindowRateLimiter` | Atomic bounded counters and namespaced state; explicit open/closed backend failure behavior | [Rate limiting](guides/rate-limiting.md) · [examples](https://github.com/hasansajedi/trustrail/tree/main/examples) (`rate_limiting.py`, `redis_rate_limiting.py`) |
| Adaptive red-team gate | `PromptInjectionRegressionGate` and `python -m trustrail.testing.red_team` | Seeded attack mutations, benign controls, minimum detection rate, maximum false-positive rate, and corpus regression | [Guide](guides/red-team-gates.md) · [example](https://github.com/hasansajedi/trustrail/blob/main/examples/red_team_gate.py) |
| AI trustworthiness campaigns | `AITestCampaignRunner` and campaign models | Versioned multi-layer cases, repetitions, confidence intervals, baseline comparison, waivers, and content-safe evidence | [Guide](guides/ai-testing-release-gates.md) |
| Framework adapters | FastAPI middleware/dependencies, LangChain callback, LlamaIndex observer, OpenAI message adapter | Guard checks at framework-specific input, output, retrieval, tool, and message boundaries | [Integrations](examples.md#framework-and-provider-integrations) |
| CLI | `trustrail check`, `validate-config`, `explain` | Local content checks, configuration validation, and rule explanations | [CLI](cli.md) |

## Combining controls safely

The catalog describes separate enforcement boundaries, not interchangeable
features. For example, an MCP token can authorize a tool call, but it does not
validate the tool schema, authenticate a JSON-RPC response, isolate another MCP
server, approve a financial action, or authorize the downstream database row.

For production deployments:

- derive identity and authorization inputs outside the model;
- use the safe or authorized object returned by each control downstream;
- use shared atomic state implementations when more than one process can handle
  a request;
- keep signing, vault, policy, approval, and audit infrastructure outside agent
  control; and
- read each linked guide's assumptions and residual-risk section before relying
  on the control.
