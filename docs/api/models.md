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

## Resource consumption budgets

Resource models bind input and expected output to authenticated principal,
tenant, session, request, and operation identity. `ResourceBudgetManager`
atomically reserves concurrency, request, retry, tool-loop, duration, and token
budgets; `BoundedDecompressor` rejects compressed amplification before parsing.

::: trustrail.models.resource
    options:
      members: true

::: trustrail.resource.ResourceBudgetManager
    options:
      members: true

::: trustrail.resource.BoundedDecompressor
    options:
      members: true

## Tool authorization

`ToolAuthorizationPolicy` inventories exact, least-privilege capabilities.
`ToolAuthorizationRequest` binds an invocation to trusted identity, intent,
ownership, scope, approval, and execution context. `ToolAuthorizer` returns a
short-lived lease only when every check succeeds. Optional
`ToolSemanticAuthorizationPolicy` operations bind arguments to trusted facts,
restrict sequences and labeled data flows, and require `ToolExecutionReport`
postcondition evidence before the chain can continue.

::: trustrail.models.agency
    options:
      members: true

::: trustrail.agency.ToolAuthorizer
    options:
      members: true

::: trustrail.agency.ToolExecutionBudget
    options:
      members: true

## MCP tool-definition integrity

MCP definition models bind complete model-visible metadata to signed discovery
and approval snapshots. `MCPToolDefinitionGuard` scans definitions together,
detects ambiguous or shadowing identities, and emits content-free field diffs
when the live definition changes before execution.

::: trustrail.models.mcp
    options:
      members: true

::: trustrail.mcp.MCPToolDefinitionGuard
    options:
      members: true

## MCP message integrity

`MCPMessageEnvelope` binds the complete JSON-RPC payload to trusted peer, user,
agent, recipient, session, direction, approved tool definition, time, and nonce
state. `MCPMessageSigner` produces Ed25519 envelopes;
`MCPMessageVerifier` authenticates them and claims replay state before returning
a defensive payload copy.

::: trustrail.models.mcp_messages
    options:
      members: true

::: trustrail.mcp_messages
    options:
      members: true

## MCP OAuth authorization

`MCPOAuthResourceServer` validates a strict request-bound JWT access-token
profile, filters `tools/list`, and enforces exact tool, scope, and argument
resources for `tools/call`. `MCPOAuthDownstreamBroker` issues exchanged or
workload-owned credentials without forwarding the caller bearer token.

::: trustrail.models.mcp_oauth
    options:
      members: true

::: trustrail.mcp_oauth
    options:
      members: true

## MCP server onboarding

`MCPServerManifest` declares publisher, pinned source and version, exact command,
transport, filesystem, network, secret references, scopes, and sandbox needs.
`MCPServerOnboardingGuard` binds those capabilities to explicit consent,
external sandbox evidence, optional deployment policy, and a short-lived permit
that is rechecked before connection.

::: trustrail.models.mcp_onboarding
    options:
      members: true

::: trustrail.mcp_onboarding
    options:
      members: true

## MCP server isolation

`MCPServerIsolationPolicy` defines independent server, namespace, credential,
principal, tool, and data-flow boundaries. `MCPServerIsolationGateway` jointly
inspects definition inventories and completely mediates calls using
integrity-bound, source-labeled results, explicit edges, redaction and approval
hooks, and content-free audit evidence.

::: trustrail.models.mcp_isolation
    options:
      members: true

::: trustrail.mcp_isolation
    options:
      members: true

## Agent goal integrity

Goal manifests bind an authorized objective, constraints, owner, approval
context, actions, delegates, session, and execution. `GoalIntegrityGuard`
validates every proposed plan step and material mutation while emitting
content-free audit evidence.

::: trustrail.models.goal
    options:
      members: true

::: trustrail.goal_integrity.GoalIntegrityGuard
    options:
      members: true

::: trustrail.goal_integrity.GoalExecutionState
    options:
      members: true

## Delegated agent identity

Identity models preserve the complete human/service/agent/sub-agent lineage and
bind each short-lived capability to a tenant, audience, purpose, scope, expiry,
and maximum depth. `DelegatedIdentityAuthorizer` verifies exact issuance,
narrowing, presenter identity, revocation, and request-bound step-up/JIT grants.

::: trustrail.models.delegated_identity
    options:
      members: true

::: trustrail.delegated_identity.DelegatedIdentityAuthorizer
    options:
      members: true

## Isolated dynamic execution

Execution models explicitly bind source or argv to an approved runtime and
filesystem, network, environment, package, resource, exit, and output policy.
`CodeExecutionAuthorizer` issues a short-lived lease only for authenticated
sandbox evidence and releases output only after terminal report and cleanup
verification.

::: trustrail.models.code_execution
    options:
      members: true

::: trustrail.code_execution.CodeExecutionAuthorizer
    options:
      members: true

## Cascading failure containment

Dependency models declare health, criticality, tenant-scoped failure domains,
cross-domain fallbacks, and sliding-window thresholds. `FailureContainmentManager`
issues single-use permits, authenticates outcomes, atomically guards retries and
side effects, and emits content-free events for degraded mode and recovery.

::: trustrail.models.failure_containment
    options:
      members: true

::: trustrail.failure_containment.FailureContainmentManager
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

## Training-data labeling integrity and bias

Training-data policy models approve the necessary features, sensitive handling,
label writers and approvers, transformation implementations, annotation-set
digest, quality thresholds, and provider-neutral bias comparisons.

::: trustrail.models.training_data
    options:
      members: true

::: trustrail.training_data
    options:
      members: true

## GenAI data lifecycle

Lifecycle models bind classification, purpose, residency, retention, training
consent, legal holds, subject references, external locations, and derivation
lineage. `DataLifecycleManager` completely mediates registration, derivation,
use, tombstone-first deletion, and connector verification.

::: trustrail.models.data_lifecycle
    options:
      members: true

::: trustrail.data_lifecycle
    options:
      members: true

## System prompt leakage

`SystemPromptTemplate` requires explicit data classification before rendering.
`SystemPromptValidator` rejects sensitive values and authorization logic before
provider submission. `SystemPromptReference` keeps the submitted prompt available
for bounded output comparison without including it in normal serialization.

::: trustrail.models.system_prompt
    options:
      members: true

::: trustrail.system_prompt.SystemPromptValidator
    options:
      members: true

::: trustrail.system_prompt.SystemPromptLeakageDetector
    options:
      members: true

## Vector and embedding workflows

The vector models carry source, trust, access, content, embedding, index, and
namespace lineage. `SecureVectorWorkflow` verifies untrusted store hits against
an authoritative catalog before RAG context assembly.

::: trustrail.models.vector
    options:
      members: true

::: trustrail.vector.SecureVectorWorkflow
    options:
      members: true

## Evidence-backed grounding

Grounding models bind exact claims and citations to immutable evidence
provenance, independent relation assessments, confidence, impact domain, and
time-bound review. `EvidenceGroundingVerifier` returns content-free findings and
downstream provenance signals before output delivery.

::: trustrail.models.grounding
    options:
      members: true

::: trustrail.grounding.EvidenceGroundingVerifier
    options:
      members: true
