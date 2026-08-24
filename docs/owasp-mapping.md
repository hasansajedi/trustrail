# OWASP LLM Top 10:2025 mapping

This table summarizes trustrail coverage against the OWASP Top 10 for LLM
Applications 2025. It is an engineering aid, not evidence of compliance or
complete mitigation.

| OWASP LLM risk | trustrail rules and APIs | Additional controls required |
| --- | --- | --- |
| **LLM01:2025 Prompt Injection** | PI-001 through PI-017 cover direct/indirect override, jailbreak, metadata poisoning, token smuggling, tool responses, encoding, multilingual attacks, payload splitting, adversarial suffixes, extracted multimodal content, invisible Unicode channels, and cross-boundary assembly; RAG-004 preserves provenance; MEM-001 protects persistent writes | Pattern detection cannot cover every semantic attack. Require least privilege, application-assigned trust, deterministic tool authorization, trusted extraction, egress controls, approval boundaries, and application-specific red teaming |
| **LLM02:2025 Sensitive Information Disclosure** | SD-001 through SD-016 detect PII, financial data, credentials, provider API tokens, and high-entropy secrets; SD-017 compares output with caller-supplied `ProtectedData`; `SensitiveDataMode` provides default, redact, block, and explicit allow policies; findings, audit events, and integration error logs are content-free | Retrieval authorization, tenant isolation, data minimization, consent and retention controls, provider-side DLP, credential rotation, and privacy-preserving model/training controls |
| **LLM03:2025 Supply Chain** | SC-001 API response integrity plus RAG provenance and trust rules | Dependency and model pinning, provenance signing, SBOMs, CI scanning, and vendor review |
| **LLM04:2025 Data and Model Poisoning** | RAG provenance/instruction controls and MEM-001 persistent-memory approval | Dataset governance, anomaly detection, trusted labeling, memory ownership/expiry, and index rebuild procedures |
| **LLM05:2025 Improper Output Handling** | OS-001 HTML injection, OS-002 path traversal, OS-003 shell metacharacters, OS-004 suspicious URLs, OS-005 unsafe protocols, and OS-006 markdown images | Contextual escaping, CSP, parameterized queries, sandboxing, and deterministic downstream validation |
| **LLM06:2025 Excessive Agency** | EA-001 agent step limit, EA-002 tool-call frequency, EA-003 recursion depth, TL-001 tool allowlist, TL-002 argument validation, and TL-003 plugin permission scope | Authorization outside the model, scoped credentials, transaction limits, and human approval for irreversible actions |
| **LLM07:2025 System Prompt Leakage** | MT-002 system-prompt extraction probes and `ProtectedData` verbatim-disclosure checks | Keep secrets out of prompts, separate authorization from prompts, and minimize internal configuration exposed to models |
| **LLM08:2025 Vector and Embedding Weaknesses** | RAG-001 through RAG-004 provenance, untrusted-instruction, trust, and context-label controls | Tenant-isolated indexes, retrieval authorization, embedding access control, source validation, and poisoning monitoring |
| **LLM09:2025 Misinformation** | GR-001 hallucination indicator, GR-002 absolute claim, and GR-003 invented citation | Source verification, calibrated uncertainty, domain evaluations, and human review gates |
| **LLM10:2025 Unbounded Consumption** | RL-001 input length, RL-002 token estimate, RL-003 message count, RL-004 repetitive pattern, and RL-005 cumulative token budget | Per-user quotas, rate limits, cost budgets, timeouts, concurrency bounds, and network egress limits |

Coverage depends on the selected `GuardStage`, configuration, custom rules, and
application enforcement. Review the [threat model](security/threat-model.md) and
test against threats specific to your system.
