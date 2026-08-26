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

Tool execution is a separate complete-mediation boundary:

```
Model proposal → Guard TOOL_REQUEST scan → ToolAuthorizer → Downstream service
                                             ├── Capability manifest
                                             ├── Principal / intent / ownership
                                             ├── Approval verifier
                                             └── ToolExecutionBudget
```

## Fail Modes

- **CLOSED** (default): Block on provider/rule failure
- **OPEN**: Allow with warning on failure
