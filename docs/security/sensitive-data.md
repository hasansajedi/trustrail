# Sensitive information disclosure

trustrail provides application-layer controls for
[OWASP LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/).
Sensitive-data checks run across user and model messages, system prompts, RAG
and external content, tool inputs and outputs, agent actions, memory, and final
output.

Built-in rules detect email addresses, phone numbers, government identifiers,
payment cards, JWTs, bearer and named API tokens, common provider tokens, cloud
credentials, private keys, credential-bearing database URLs, and contextual
high-entropy secrets. `SD-015` covers common GitHub, GitLab, Slack, Stripe,
OpenAI-compatible, Anthropic, Google, and npm token shapes; `SD-016` detects
password, client-secret, and private-token assignments.

## Choose a handling policy

```python
from trustrail import Guard, GuardConfig, GuardStage, SensitiveDataMode

guard = Guard(
    config=GuardConfig(sensitive_data_mode=SensitiveDataMode.REDACT),
)
safe_output = guard.protect(model_output, GuardStage.FINAL_OUTPUT)
```

| Mode | Behavior |
| --- | --- |
| `DEFAULT` | Uses each rule's native action: common PII is redacted, credentials are blocked, and low-confidence signals may warn. |
| `REDACT` | Replaces every detected value. A detector that cannot make a safe replacement fails closed. |
| `BLOCK` | Blocks any sensitive-data finding. |
| `ALLOW` | Returns the original value while retaining content-free findings and audit metadata. Use only for an explicitly accepted, trusted workflow. |

Risk scores describe what was detected even when an explicit `REDACT` or
`ALLOW` policy handles the finding. Always use `result.output_value` or
`Guard.protect()` downstream; do not continue with the original input after a
redaction.

## Protect private RAG and system context

Patterns cannot identify arbitrary proprietary material. Pass private source
values as `ProtectedData` when checking generated output:

```python
from trustrail import Guard, GuardStage, ProtectedData

private_context = crm_document.content
result = Guard.strict().check(
    model_output,
    GuardStage.FINAL_OUTPUT,
    protected_data=[ProtectedData(value=private_context)],
)
if result.is_blocked:
    return "I cannot disclose that private context."
```

`SD-017` detects case-insensitive verbatim reproduction of the full protected
value or a sentence/line of at least 20 characters. Whitespace changes are
tolerated. Configure `min_match_chars` and `case_sensitive` per value where a
different false-positive tradeoff is appropriate.

`ProtectedData.value` is excluded from its representation and Pydantic
serialization. It is passed directly to the detector and is never copied into
guard context, findings, audit events, or exception messages.

## Logging and errors

Sensitive findings contain only a rule ID, category, severity, message,
offsets, and content-free metadata. The safe replacement is available only on
`GuardResult.transformed_value`; it is not copied into every finding. This
prevents one detector's finding from retaining a different secret that a later
detector would redact.

```python
for finding in result.findings:
    logger.warning(
        "sensitive output",
        extra={"rule_id": finding.rule_id, "severity": finding.severity.value},
    )
```

Do not serialize `GuardResult.value`, which necessarily contains the value the
caller asked trustrail to inspect. Audit sinks intentionally record lengths and
finding summaries rather than content. Integration error logs record exception
types, not exception strings, because upstream exceptions can contain request
data.

## Assumptions, limitations, and residual risk

- Pattern detectors are deterministic and explainable, but regional PII and
  newly introduced credential formats require custom rules or provider-side
  DLP. IP detection is disabled in `SensitiveDataPolicy` by default because of
  its false-positive rate.
- `ProtectedData` catches verbatim or whitespace-modified fragments, not
  paraphrases, translations, semantic summaries, model-training extraction, or
  membership-inference attacks.
- Detection does not replace retrieval authorization, tenant isolation, least
  privilege, retention controls, user consent, or restrictions on model-provider
  training and storage.
- Blocking delivery does not prove a credential was never exposed to another
  model, trace, callback, or service. Revoke and rotate credentials that crossed
  an untrusted boundary.
- Redaction placeholders reveal the type of data detected. Use `BLOCK` where
  even that signal is too sensitive.

Add a [custom rule](../custom-rules.md) for internal identifiers and test it
against representative positive, negative, and bypass cases.
