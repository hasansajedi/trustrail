# Architecture

## Pipeline Stages

aiRail operates at discrete stages of the LLM pipeline:

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
4. **Policy** — Apply configured policies
5. **Transform** — Redact/transform if needed
6. **Audit** — Emit structured audit events

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

## Fail Modes

- **CLOSED** (default): Block on provider/rule failure
- **OPEN**: Allow with warning on failure
