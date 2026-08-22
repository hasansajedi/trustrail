# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

To report a security vulnerability, please email: security@trustrail.io

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

You can expect:
- Acknowledgment within 48 hours
- A status update within 7 days
- A fix within 30 days for critical issues

## Security Design Principles

trustrail follows these principles:

1. **Fail-closed by default** — When in doubt, block
2. **Defense in depth** — Multiple detection layers
3. **No eval/exec** — No dynamic code execution
4. **Bounded processing** — No ReDoS-vulnerable regexes
5. **Privacy-preserving audit** — Logs metadata, never content
6. **Minimal dependencies** — Core has only Pydantic
7. **Supply chain security** — Dependencies audited with pip-audit
