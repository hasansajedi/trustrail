# Content safety

The `CONTENT_SAFETY` rule category provides baseline content filtering for
customer-facing, educational, and workplace LLM deployments.

## Rules

| Rule ID | Name | Default action | Severity |
| --- | --- | --- | --- |
| CS-001 | Toxicity / Hate Speech | `BLOCK` | `CRITICAL` |
| CS-002 | Profanity / Explicit Content | `BLOCK` | `HIGH` |

## CS-001 `ToxicityRule`

Detects the most unambiguous forms of harmful content in LLM output:

- **Dehumanising language** — statements that describe people as subhuman,
  vermin, or call for their elimination based on protected characteristics
  (race, religion, gender, sexual orientation, disability, nationality)
- **Explicit threats** — direct statements of intent to harm ("I will kill
  you", "watch your back")
- **Hate-speech slurs** — racial, ethnic, and identity-based slurs

The rule uses exact-match patterns to minimise false positives on educational
or journalistic text discussing these topics.

```python
from aiRail.rules.output import ToxicityRule
from aiRail.models.enums import GuardStage

rule = ToxicityRule()
result = rule.evaluate(llm_output, context)
if result.is_blocked:
    return safe_fallback_response()
```

## CS-002 `ProfanityRule`

Enforces acceptable-use policies by detecting:

- **Profanity** — common swear words and vulgar language
- **Explicit sexual content** — language describing sexual acts or anatomy
  in a non-medical context

Both checks are enabled by default and can be toggled independently:

```python
from aiRail.rules.output import ProfanityRule

# Detect only explicit sexual content, allow profanity
rule = ProfanityRule(check_profanity=False, check_explicit=True)
result = rule.evaluate(llm_output, context)
```

## OWASP mapping

Both CS-001 and CS-002 address **OWASP LLM02** (Insecure Output Handling).
Harmful or offensive LLM output that reaches end users without filtering is
a primary risk in production deployments.
