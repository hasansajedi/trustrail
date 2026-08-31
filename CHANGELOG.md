# Changelog

All notable changes to trustrail will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- First-class async rules and external moderation, prompt-injection, sensitive-data,
  and grounding providers with deterministic execution order, bounded concurrency,
  per-check deadlines, cancellation, and explicit fail-open/fail-closed behavior.
- OWASP ASI01 agent goal-integrity controls with immutable manifests, bound plan
  steps and delegation, exact mutation approval, cumulative drift detection, and
  content-free audit evidence.

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
