# Sensitive data

trustrail detects common personal and secret-bearing values, including email
addresses, phone numbers, payment cards, JWTs, bearer tokens, AWS access keys,
private keys, database URLs, and high-entropy strings.

```python
from trustrail import Guard, GuardStage

guard = Guard.balanced()
result = guard.check(model_output, GuardStage.FINAL_OUTPUT)
for finding in result.findings:
    logger.warning(
        "sensitive output",
        extra={"rule_id": finding.rule_id, "severity": finding.severity.value},
    )
```

Checks apply to input, system prompts, output, tool responses, and memory stages
according to the [policy matrix](../policies.md).

## Handling findings

Do not copy the detected value into logs, metrics, traces, or error responses.
Prefer rule ID, category, severity, offsets, and request ID. Rotate any credential
that may have crossed an untrusted boundary; blocking delivery does not prove the
credential was never exposed elsewhere.

Pattern detection cannot know your business-specific identifiers. Add a
[custom rule](../custom-rules.md) for internal project names, customer IDs, or
proprietary formats, and use provider-side DLP where required by policy.
