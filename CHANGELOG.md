# Changelog

All notable changes to aiRail will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-01-01

### Added
- Initial release of aiRail
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

[Unreleased]: https://github.com/hasansajedi/aiRail/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hasansajedi/aiRail/releases/tag/v0.1.0
