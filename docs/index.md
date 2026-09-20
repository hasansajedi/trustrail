# trustrail Documentation

**Production-grade open-source Python library for GenAI/LLM guardrails**

## Overview

trustrail provides comprehensive security guardrails for LLM applications. It protects against:

- Prompt injection (direct, indirect, jailbreak)
- Sensitive data leakage (PII, secrets, payment cards)
- Unsafe outputs (XSS, path traversal, shell injection)
- SSRF / dangerous URLs
- Excessive agent agency
- Misinformation and unsafe overreliance
- Resource abuse
- MCP message tampering and replay
- Inter-agent impersonation, replay, reordering, and unauthorized delegation
- Misleading or incomplete approval prompts for high-impact agent actions
- MCP cross-server tool shadowing, credential crossover, and unauthorized data flows
- Data-lifecycle metadata downgrade, incompatible reuse, and incomplete deletion

## Navigation

- [Installation](installation.md)
- [Quick Start](quickstart.md)
- [Concepts](concepts.md)
- [Architecture](architecture.md)
- [Configuration](configuration.md)
- [Security Threat Model](security/threat-model.md)
- [GenAI Data Lifecycle and Verified Deletion](security/data-lifecycle.md)
- [Authenticated Inter-Agent Communication](security/inter-agent-communication.md)
- [Tamper-Resistant High-Impact Approvals](security/high-impact-approvals.md)
- [FAQ](faq.md)
