# Architecture

## Pipeline Stages

trustrail operates at discrete stages of the LLM pipeline:

```
User Input → System Prompt → LLM Request
                                  ↓
                             LLM Response
                                  ↓
                          Tool Request/Response
                                  ↓
                            Final Output
```

## Evaluation Pipeline

1. **Normalization** — Decode obfuscation (HTML entities, URL encoding, base64, homoglyphs)
2. **Validate** — Check resource limits, format validity
3. **Detect** — Pattern matching, heuristics
4. **Policy** — Apply configured content policies
5. **Authorize** — At tool boundaries, bind the exact request to trusted identity,
   intent, ownership, scope, approval, and execution budget
6. **Transform** — Redact/transform if needed
7. **Audit** — Emit structured audit events

## Component Architecture

```
Guard
  ├── Policies
  │   ├── PromptInjectionPolicy → Rules
  │   ├── SensitiveDataPolicy → Rules
  │   ├── OutputSafetyPolicy → Rules
  │   ├── RAGPolicy → Rules
  │   ├── ToolPolicy → Rules
  │   ├── ResourcePolicy → Rules
  │   └── AgentPolicy → Rules
  ├── AuditSink (LoggingAuditSink / MemoryAuditSink / OtelAuditSink)
  └── StateBackend (MemoryStateBackend / RedisStateBackend)
```

### State backends

`MemoryStateBackend` provides bounded, process-local storage for development and
single-worker services. `RedisStateBackend` provides shared asynchronous state for
multi-worker and multi-replica deployments through redis-py's connection pool.

Redis physical keys use
`<namespace>:v1:<sha256(logical-key)>`. Values use a versioned JSON envelope, and
counter updates use an atomic Lua operation that initializes expiration only when
the counter is created. The hash keeps tenant and session identifiers out of Redis
keys; `build_state_key()` canonically separates identity components before hashing
them so attacker-controlled delimiters cannot create key collisions.

Redis failures are fail-closed by default and raise `StateBackendError` without
including the key, value, URL, or credentials in the public message. Explicit
fail-open mode returns an empty read, treats writes and deletes as no-ops, and
returns the requested delta for counters. This degraded mode weakens distributed
limits and must be selected deliberately. Owned clients expose `aclose()` and an
async context manager so pooled connections are released during shutdown.

Tool execution is a separate complete-mediation boundary:

```
Model proposal → Guard TOOL_REQUEST scan → ToolAuthorizer → Downstream service
                                             ├── Capability manifest
                                             ├── Principal / intent / ownership
                                             ├── Approval verifier
                                             └── ToolExecutionBudget
```

For delegated agents, authenticate and authorize identity before constructing
the tool request:

```
Authenticated workload + delegation chain → DelegatedIdentityAuthorizer
                                                ↓ short-lived ToolPrincipal
Model proposal + trusted intent → ToolAuthorizer → Downstream service
```

This identity boundary validates the complete delegation lineage and prevents a
model from selecting its identity, tenant, audience, purpose, or privileges.

Dynamic code execution has its own boundary outside the application process:

```
Typed source/argv request + authenticated sandbox attestation
                              ↓
                    CodeExecutionAuthorizer → external isolated broker
                              ↑                     ↓
                    verified output ← signed report + cleanup evidence
```

trustrail performs admission and report verification only. The external broker
must provide OS isolation and enforce the authorized filesystem, network,
environment, package, process, resource, and cleanup policy.

## Fail Modes

- **CLOSED** (default): Block on provider/rule failure
- **OPEN**: Allow with warning on failure
