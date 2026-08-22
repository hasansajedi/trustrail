# OWASP LLM mapping

This table summarizes trustrail coverage against common OWASP risks. It is an
engineering aid, not evidence of compliance or complete mitigation.

| OWASP LLM risk | trustrail rules | Additional controls required |
| --- | --- | --- |
| **LLM01** Prompt injection | PI-001 direct override, PI-002 jailbreak, PI-003 system override, PI-004 indirect injection, PI-005 tool manipulation, PI-006 data exfiltration, PI-015 extracted multimodal content, PI-016 invisible Unicode channel stripping, RAG-004 provenance-labeled data envelope, MEM-001 persistent memory classification/approval, adaptive red-team regression gate, MT-002 system prompt extraction | Least privilege, application-assigned trust, manual semantic red teaming, trusted OCR/transcription and approval boundaries |
| **LLM02** Insecure output handling | OS-001 HTML injection, OS-002 path traversal, OS-003 shell metachar, OS-004 suspicious URL, OS-005 unsafe protocol, OS-006 markdown image | Contextual escaping, CSP, parameterised queries |
| **LLM04** Model denial of service | RL-001 input length, RL-002 token estimate, RL-003 message count, RL-004 repetitive pattern, RL-005 cumulative token budget | Per-user rate limits, network egress limits |
| **LLM05** Supply chain | SC-001 API response integrity, RAG-001 provenance, RAG-002 untrusted instruction, RAG-003 source trust, RAG-004 context label integrity | Dependency pinning, provenance signing, CI scanning |
| **LLM06** Sensitive information disclosure | SD-001 email, SD-002 phone, SD-003 IP address, SD-004 payment card, SD-005 JWT, SD-006 bearer token, SD-007 AWS key, SD-008 private key, SD-009 database URL, SD-010 high-entropy secret | DLP, access control, secret rotation |
| **LLM07** Insecure plugin design | TL-001 tool allowlist, TL-002 argument validation, TL-003 plugin permission scope | Plugin sandboxing, authorization outside the model |
| **LLM08** Excessive agency | EA-001 agent step limit, EA-002 tool call frequency, EA-003 recursion depth | Human approval for irreversible actions, scoped credentials |
| **LLM09** Misinformation / overreliance | GR-001 hallucination indicator, GR-002 absolute claim, GR-003 invented citation | Source verification, human review gates |
| **LLM10** Model theft | MT-001 model extraction probe, MT-002 system prompt extraction | Rate limiting, anomaly detection on query patterns |
| Data/model poisoning | RAG-001/002/003/004 retrieval controls, MEM-001 persistent memory approval | Dataset governance, memory ownership/expiry, and index rebuild procedures |
| Vector/embedding weaknesses | RAG-001 provenance, RAG-003 source trust | Tenant isolation and retrieval authorization |
| URL/SSRF | URL-001 through URL-005 scheme, private IP, metadata service, credential, and domain checks | Network egress allowlists |

Coverage depends on the selected `GuardStage`, configuration, custom rules, and
application enforcement. Review the [threat model](security/threat-model.md) and
test against threats specific to your system.
