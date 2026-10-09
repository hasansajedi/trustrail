# trustrail documentation

trustrail is a typed Python security library for GenAI applications. It combines
content guardrails with authorization, identity, integrity, isolation, lifecycle,
and operational controls for agents, tools, RAG, persistent state, and MCP.

## Choose where to start

| If you need to... | Start here |
| --- | --- |
| Add input and output guardrails | [Quick start](quickstart.md) |
| See every implemented control | [Feature and control catalog](features.md) |
| Run a complete working example | [Runnable examples](examples.md) |
| Protect an agent or its tools | [Protect agents](guides/protect-agents.md) and [protect tools](guides/protect-tools.md) |
| Secure an MCP deployment | [MCP security stack](#mcp-security-stack) |
| Map controls to OWASP guidance | [OWASP mapping](owasp-mapping.md) |
| Understand trust assumptions | [Threat model](security/threat-model.md) |
| Find a class or typed model | [API reference](api/index.md) |

## What the library implements

### Content and model boundaries

- direct, indirect, encoded, and cross-boundary prompt-injection detection;
- PII, protected-data, secret, and credential leakage controls;
- context-aware HTML, SQL, shell, URL, path, template, log, XML, and tool-output
  handling;
- RAG provenance, poisoning, vector-lineage, and evidence-grounding checks;
- system-prompt construction and leakage protection; and
- cross-chunk streaming checks plus awaited external safety providers.

### Agent identity and authority

- least-privilege tool authorization with semantic preconditions,
  postconditions, data-flow rules, and execution budgets;
- delegated agent identity, goal-integrity enforcement, step-up/JIT privilege,
  exact high-impact approvals, and signed inter-agent messages;
- model-blind credential brokering and signed runtime capability manifests;
- isolated generated-code authorization, resource budgets, rogue-agent runtime
  invariants, and cascading-failure containment; and
- signed persistent workflow checkpoints with replay-safe resume authorization.

### Data, state, and model governance

- persistent-memory approval, provenance, taint, revalidation, and rebuild;
- signed data labels and downgrade-resistant propagation;
- purpose, residency, retention, consent, derivation, tombstone, and verified
  deletion lifecycle controls;
- tenant-bound cache, memory, adapter, state, and inference-batch isolation;
- AI supply-chain pinning, ingestion poisoning checks, and training-data label
  and bias governance; and
- shared Redis state for distributed rate limits and other atomic controls.

### MCP security stack

MCP deployments normally need all five layers; each addresses a different trust
boundary:

1. [Tool-definition integrity](security/mcp-tool-integrity.md) validates and pins
   the complete model-visible schema.
2. [Server onboarding](security/mcp-server-onboarding.md) verifies publisher,
   source, command, transport, capabilities, consent, and sandbox evidence.
3. [OAuth authorization](security/mcp-oauth.md) validates request-bound access
   tokens, filters discovery, authorizes tool resources, and prevents bearer
   passthrough.
4. [Message integrity](security/mcp-message-integrity.md) signs JSON-RPC traffic
   with peer, user, session, definition, freshness, and replay binding.
5. [Server isolation](security/mcp-server-isolation.md) separates namespaces,
   credentials, principals, and cross-server data flows.

These controls complement transport security, downstream service authorization,
network egress policy, protected key management, and deployment isolation. They
do not replace those controls.

## A typical protected request

1. Derive user, tenant, session, and authorization context from authenticated
   server-side state.
2. Guard untrusted input and retrieved content before prompt assembly.
3. Keep secrets out of model-visible data and resolve credentials only inside a
   trusted connector.
4. Authorize the exact tool, arguments, resources, effects, and execution
   environment before dispatch.
5. Validate tool and model output for its concrete destination before use.
6. Persist only integrity-bound, tenant-bound, lifecycle-aware state.
7. Emit content-free audit evidence and turn incidents into deterministic
   regression cases.

The [feature catalog](features.md) maps each step to its public API, detailed
guide, and runnable example.

## Installation

```bash
pip install trustrail
```

Optional integrations are installed separately, for example
`trustrail[openai]`, `trustrail[fastapi]`, `trustrail[redis]`, or
`trustrail[all]`. See [installation](installation.md) for the complete matrix.
