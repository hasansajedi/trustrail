# Changelog

All notable changes to trustrail will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GenAI data-lifecycle controls with integrity-bound classification, purpose,
  residency, retention, training-consent, legal-hold, subject, storage, and
  derivation labels; fail-closed use authorization; cascading tombstone-first
  deletion plans; connector receipts and deletion verification; and content-free
  audit evidence.
- OWASP AISVS C5.2.7 controls for Ed25519-signed, content-bound classification
  labels; conservative joins across transformations; complete provider,
  retrieval, persistence, logging, tool, and output boundary enforcement; and
  content-safe lineage evidence ([#82](https://github.com/hasansajedi/trustrail/issues/82)).
- OWASP MCP multi-server isolation controls with independent server, namespace,
  credential, principal, and tool trust domains; explicit labeled data-flow
  edges; cross-origin instruction and shadowing detection; gateway redaction,
  approval, resource, and content-free audit hooks.
- OWASP MCP message-level integrity controls with mutually verifiable Ed25519
  request and response envelopes, authenticated identity, session, and tool
  bindings, freshness checks, bounded atomic replay protection,
  unsigned-downgrade rejection, and content-free audit events.
- OWASP MCP tool-definition integrity controls with complete canonical schema
  pinning, authenticated discovery and approval snapshots, pre-execution rug-pull
  detection, nested metadata scanning, shadowing/confusable-name rejection, and
  content-free definition diffs that require renewed consent.
- First-class async rules and external moderation, prompt-injection, sensitive-data,
  and grounding providers with deterministic execution order, bounded concurrency,
  per-check deadlines, cancellation, and explicit fail-open/fail-closed behavior.
- OWASP ASI01 agent goal-integrity controls with immutable manifests, bound plan
  steps and delegation, exact mutation approval, cumulative drift detection, and
  content-free audit evidence.
- OWASP ASI02 semantic tool controls with trusted preconditions, intent-bound
  arguments and destinations, sequence and data-flow policy, verified execution
  postconditions, chain quarantine, and compensation hooks.
- OWASP ASI03 delegated identity controls with immutable human/service/agent
  lineage, short-lived scope/audience/purpose-bound capabilities, ancestor
  revocation, privilege narrowing, and request-bound step-up and JIT grants.
- OWASP ASI05 dynamic-execution controls with explicit runtime and isolation
  policy, dangerous import and shell rejection, authenticated sandbox admission,
  bounded single-use leases, and verified output, resource, exit, and cleanup
  evidence.
- OWASP ASI06 persistent-memory taint controls with integrity-bound provenance,
  identity, tenant, purpose, transformations, and dependencies; privileged-write
  approval, split-entry and laundering detection, atomic retrieval checks,
  lineage-wide remediation, exact revalidation, and safe rebuild hooks.
- OWASP ASI08 cascading-failure controls with typed dependency and failure-domain
  policy, tenant-isolated circuit breakers, integrity-pinned fallbacks, atomic
  retry and side-effect admission, authenticated outcomes, and deterministic
  degraded-mode, cancellation, compensation, and recovery events.
- OWASP ASI10 rogue-agent controls with signed runtime invariants, correlated
  behavior and stop-compliance detection, deterministic suspension, credential
  revocation, pending-action cancellation and state quarantine, plus isolated,
  authenticated single-use recovery ([#81](https://github.com/hasansajedi/trustrail/issues/81)).

## [0.1.2] - 2026-08-31

### Added

- OWASP-aligned safeguards for prompt injection, sensitive information disclosure,
  AI supply-chain risks, data and model poisoning, unsafe output handling,
  excessive agency, system prompt leakage, vector and embedding workflows,
  misinformation and overreliance, and unbounded resource consumption.
- End-to-end developer examples covering core guards, configuration, RAG,
  streaming, agents, framework integrations, observability, testing, and
  production deployment patterns.
- Production Redis state backend with pooled async connections, versioned and
  namespaced storage, collision-safe keys, atomic TTL counters, explicit fail
  modes, and clean shutdown.

### Changed

- Guard configuration now enforces configured policy and rule controls.
- LangChain and LlamaIndex integrations now await asynchronous checks and honor
  the configured fail mode.
- The OpenAI adapter now preserves multimodal content, tool calls, tool-call IDs,
  and other structured message fields.

### Fixed

- Enforced cumulative size limits and fail-mode semantics across streaming scans.
- Preserved document provenance when caller context is merged into RAG scans.
- Applied guard transformations to fully bound positional, keyword, default, and
  variadic decorator arguments.
- Made message protection fail closed without silently removing conversation
  entries.
- Made rate-limit increments and initial TTL assignment atomic across supported
  state backends.

## [0.1.1] - 2026-08-22

### Added

- Initial release of trustrail
- Core guard engine with sync and async support
- Prompt injection detection (direct, indirect, jailbreak)
- Sensitive data detection (PII, secrets, API keys)
- Output safety validation (XSS, path traversal, shell injection)
- URL/SSRF protection
- RAG security rules
- Tool call validation
- Resource limit enforcement
- Agent session tracking
- Streaming support with cross-chunk detection
- Audit event system (LoggingAuditSink, NullAuditSink, MemoryAuditSink)
- OpenTelemetry integration (optional)
- FastAPI middleware integration
- OpenAI message/response adapter
- LangChain callback handler stub
- LlamaIndex observer stub
- CLI with check, validate-config, and explain commands
- Testing utilities (FakePromptInjectionProvider, FakeModerationProvider, etc.)
- Guard profiles: default, balanced, strict
- Decorator API: @guard.input(), @guard.output(), @guard.tool()
- Fail-open/fail-closed per guard configuration

[Unreleased]: https://github.com/hasansajedi/trustrail/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/hasansajedi/trustrail/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/hasansajedi/trustrail/releases/tag/v0.1.1
