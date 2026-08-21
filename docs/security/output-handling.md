# Insecure output handling

Model output is untrusted data. aiRail detects common HTML injection, path
traversal, shell metacharacters, unsafe protocols, suspicious URLs, and external
Markdown image patterns at output stages. It also flags output that carries
overconfidence signals or hallucination-prone language.

```python
result = guard.check(model_output, GuardStage.LLM_RESPONSE)
if result.is_blocked:
    return fallback_response
safe_output = result.output_value
```

## Output safety rules (OS-001 – OS-007)

| Rule ID | Name | What it detects |
| --- | --- | --- |
| OS-001 | HTML Injection | `<script>`, event handlers, and XSS payloads |
| OS-002 | Path Traversal | `../` sequences and absolute path references |
| OS-003 | Shell Metachar | Shell metacharacters that could reach a subprocess |
| OS-004 | Suspicious URL | Obfuscated, redirecting, or typosquatting URLs |
| OS-005 | Unsafe Protocol | `javascript:`, `data:`, `vbscript:` and similar |
| OS-006 | Markdown External Image | `![...]()` patterns that load remote tracking pixels |
| OS-007 | Dangerous Code Construct | `eval`, `exec`, `subprocess`, `child_process`, download-and-execute shells |

### OS-007 `DangerousCodeConstructRule`

Warns when generated output contains code that could execute attacker-controlled
payloads: Python's `eval()`, `exec()`, `__import__()`, `subprocess.Popen()`,
`os.system()`; JavaScript's `child_process` and `new Function()`; and shell
download-and-execute one-liners (`curl … | bash`).

Default action: `WARN`. Switch to `BLOCK` when generated code is automatically
executed (e.g., agentic code-execution pipelines).

```python
from aiRail.rules.output import DangerousCodeConstructRule

rule = DangerousCodeConstructRule()
result = rule.evaluate(llm_generated_code, context)
if result.action == GuardAction.WARN:
    require_human_review(llm_generated_code)
```

Passing a guard check does not make a string safe for every interpreter. Apply a
control appropriate to the destination:

| Destination | Required control |
| --- | --- |
| HTML | Context-aware escaping and a Content Security Policy |
| SQL | Parameterized statements; never concatenate model text |
| Shell | Avoid execution; otherwise use fixed commands and validated arguments |
| Filesystem | Resolve paths and enforce an allowed root directory |
| URL fetch | Scheme/host allowlists and network egress restrictions |
| JSON | Schema validation and size/depth limits |

## Grounding rules (GR-001 – GR-004)

LLM output can be technically safe for the rendering context but still harmful
if it misleads users into over-trusting fabricated or overconfident claims.
These grounding rules address OWASP LLM09 (Misinformation):

| Rule ID | Name | Default action |
| --- | --- | --- |
| GR-001 | Hallucination Indicator | `WARN` |
| GR-002 | Absolute Claim | `WARN` |
| GR-003 | Invented Citation | `WARN` |
| GR-004 | High-Risk Domain Advice | `WARN` |
| GR-005 | Sycophancy / Factual Contradiction | `WARN` |

### GR-001 `HallucinationIndicatorRule`

Warns when the output contains uncertainty phrases that signal the model may be
fabricating content: `"as of my knowledge"`, `"I believe"`, `"please verify
this"`, `"to the best of my recollection"`.

Default action: `WARN`. Use at `LLM_RESPONSE` or `FINAL_OUTPUT`.

### GR-002 `AbsoluteClaimRule`

Warns when the output makes overconfident absolute claims: `"100 percent safe"`,
`"absolutely certain this will work"`, `"there is no doubt"`, `"always works in
production"`.

Default action: `WARN`. Escalate to `BLOCK` for high-stakes pipelines.

### GR-003 `InventedCitationRule`

Warns when the output contains citation-like patterns — DOI strings, arXiv IDs,
or `[Author et al., YYYY]` references — that may be hallucinated. These patterns
appear with lower confidence (`0.6`) to account for legitimate academic output.

Default action: `WARN`.

### GR-004 `HighRiskDomainAdviceRule`

Warns when the output gives specific medical, legal, or financial advice without
an appropriate disclaimer. Detected patterns include:

- **Medical**: `"you likely have appendicitis"`, `"take ibuprofen 800mg"`,
  `"stop taking your medication"`
- **Legal**: `"you should sue"`, `"you have a legal claim"`,
  `"file a complaint with the court"`
- **Financial**: `"you should buy NVDA"`, `"put your savings into"`,
  `"guaranteed returns"`

The rule passes automatically if the output already contains a disclaimer such
as `"not medical advice"`, `"consult a doctor"`, or `"I am not your attorney"`.

Default action: `WARN`, severity `HIGH`.

```python
from aiRail.rules.output import (
    AbsoluteClaimRule,
    HallucinationIndicatorRule,
    HighRiskDomainAdviceRule,
    InventedCitationRule,
)

guard = Guard(
    GuardConfig(...),
    extra_rules=[
        HallucinationIndicatorRule(),
        AbsoluteClaimRule(),
        InventedCitationRule(),
        HighRiskDomainAdviceRule(),
    ],
)
result = guard.check(model_output, GuardStage.LLM_RESPONSE)
```

### GR-005 `SycophancyRule`

Warns when the model unconditionally validates a user's claim or agrees with a
known false premise. Detected patterns include:

- Unconditional openers: `"You are absolutely right"`, `"That is entirely correct"`,
  `"I completely agree with you"`
- Known false-premise agreements: vaccine-autism link, flat earth, climate
  denial, moon-landing hoax

```python
from aiRail.rules.output import SycophancyRule

rule = SycophancyRule()
result = rule.evaluate(llm_output, context)
# Result is WARN — inspect finding.metadata["matched_phrase"] to surface to ops
```

Default action: `WARN`, severity `HIGH`.

Keep the model away from raw interpreter APIs. Prefer typed, narrowly scoped
tools that translate validated fields into operations.
