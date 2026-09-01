# Safe model output handling

Model output is untrusted data, even when the prompt asks the model to be safe.
trustrail implements the zero-trust output boundary recommended by
[OWASP LLM05:2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)
in two layers:

1. `Guard` detects suspicious output at `LLM_RESPONSE` or `FINAL_OUTPUT`.
2. `SafeOutputHandler` applies the control required by the actual destination.

```python
from trustrail import Guard, GuardStage, OutputContext, SafeOutputHandler

scan = Guard.balanced().check(model_output, GuardStage.FINAL_OUTPUT)
if scan.is_blocked or scan.output_value is None:
    return fallback_response

html_text = SafeOutputHandler().require(scan.output_value, OutputContext.HTML)
```

The returned HTML is encoded text, not trusted markup. A successful pattern scan
alone never makes a string safe for an interpreter.

## Destination contracts

`OutputHandlingPolicy` is fail closed. URL hosts and filesystem roots have no
permissive default, structured output needs an explicit schema, and raw
interpreter/tool contexts are rejected.

| Context | Contract |
| --- | --- |
| `TEXT` | Enforce output-size and control-character limits |
| `HTML` | Encode as HTML text, including quotes |
| `JAVASCRIPT` | Encode one JavaScript string literal and escape HTML-breaking characters |
| `MARKDOWN` | Reject raw HTML and images; validate links against exact scheme/host allowlists |
| `URL` | Require an allowed scheme and exact hostname; reject credentials and malformed URLs |
| `PATH` | Require a relative path that resolves beneath `path_root` |
| `JSON` | Reject raw use; parse once into a strict Pydantic schema with duplicate-key and size/depth checks |
| `SQL` | Reject raw queries; bind validated model text only as prepared-statement data |
| `SHELL` | Reject raw commands; use a fixed executable, `shell=False`, and one validated argv item at a time |
| `TEMPLATE` | Reject model-generated template source; pass encoded/validated data to a fixed autoescaping template |
| `TOOL` | Reject raw tool execution; validate a fixed tool name and typed arguments without executing them |
| `CODE` | Reject by default; optional review mode returns `REQUIRE_APPROVAL`, never execution permission |

### SQL, commands, and files

```python
from pathlib import Path

from trustrail import OutputHandlingPolicy, SafeOutputHandler

handler = SafeOutputHandler(
    OutputHandlingPolicy(path_root=Path("/srv/app/reports"))
)

# The query and executable are application-owned constants.
database.execute(
    "SELECT id FROM documents WHERE title = ?",
    (handler.as_sql_parameter(model_title),),
)
subprocess.run(
    ["/usr/bin/printf", "--", handler.as_command_argument(model_text)],
    shell=False,
    check=True,
)
report_path = handler.resolve_path(model_relative_path)
```

Never use `as_sql_parameter()` for table names, column names, operators, or SQL
fragments. Never let model output select the executable. The `--` separator is
still recommended because each command has its own option semantics.

### Strict structured output and tools

```python
from pydantic import BaseModel, ConfigDict

from trustrail import SafeOutputHandler


class EmailArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipient_id: int
    subject: str


handler = SafeOutputHandler()
call = handler.parse_tool_call(
    model_output,
    expected_name="send_email",
    arguments_schema=EmailArguments,
)

# Parsing creates a plan only. Apply deterministic authorization, tenant checks,
# rate limits, and out-of-band approval before an executor sees call.arguments.
assert call.requires_approval
```

`parse_json()` uses strict Pydantic validation: type coercion, unknown fields
(when the schema forbids them), duplicate keys, non-finite numbers, excessive
nesting, and excessive node counts fail closed.

## Output safety rules (OS-001 – OS-013)

All output safety rules scan the complete guard-bounded value, emit
content-free findings, and map to `LLM05:2025`.

| Rule ID | Detection |
| --- | --- |
| OS-001 | HTML injection and event handlers |
| OS-002 | Path traversal and absolute paths |
| OS-003 | Shell metacharacters |
| OS-004 | Suspicious and obfuscated URLs |
| OS-005 | Unsafe protocols |
| OS-006 | External Markdown images |
| OS-007 | Dangerous generated-code constructs |
| OS-008 | SQL injection patterns |
| OS-009 | Server-side template expressions |
| OS-010 | CRLF and forged log entries |
| OS-011 | LDAP injection patterns |
| OS-012 | XML, XPath, and XXE patterns |
| OS-013 | Insecure file paths and wrapper schemes |

OS-007 warns because code may be legitimate content. `SafeOutputHandler` still
blocks the `CODE` destination unless review mode is explicitly enabled.

## Defense in depth and residual risk

- Keep a strict Content Security Policy and framework autoescaping; never mark
  model text as trusted HTML.
- Markdown checks are intentionally conservative and not a full renderer.
  Disable raw HTML in the renderer and sanitize the renderer's final HTML.
- URL validation is syntactic and uses exact hostnames. Enforce DNS/IP checks,
  redirect validation, TLS, egress allowlists, and SSRF controls when fetching.
- Path resolution can race with symlink changes. Use descriptor-relative secure
  file APIs and appropriate filesystem permissions for privileged operations.
- Prepared statements protect data values, not dynamic identifiers or query
  structure. Use application-owned allowlists for those choices.
- Fixed argv avoids shell expansion, but target programs can interpret values as
  options, file paths, templates, or code. Apply destination-specific validation.
- Tool parsing grants no authority. Keep credentials scoped, re-check object and
  tenant authorization, cap effects, and require approval for consequential work.
- Generated code still needs sandboxing, resource/network limits, dependency
  controls, and human review. `REQUIRE_APPROVAL` is not an allow decision; use
  the [isolated execution boundary](code-execution-isolation.md) before an
  authenticated external sandbox broker.

## Grounding rules (GR-001 – GR-005)

LLM output can be technically safe for the rendering context but still harmful
if it misleads users into over-trusting fabricated or overconfident claims.
These heuristic grounding rules provide defense in depth for OWASP LLM09:2025
(Misinformation):

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

The heuristic rule passes if the output already contains a disclaimer such as
`"not medical advice"`, `"consult a doctor"`, or `"I am not your attorney"`.
That is only a false-positive reduction for this warning rule: a disclaimer does
not make consequential advice grounded and does not satisfy a human-review gate.

Default action: `WARN`, severity `HIGH`.

These rules identify language patterns but do not validate sources or establish
truth. Before releasing factual or consequential output, use the typed
`EvidenceGroundingVerifier` to check evidence integrity and trust, semantic
relations, citations, confidence disclosure, contradictions, and bound
high-impact review. See
[misinformation and unsafe overreliance](misinformation-overreliance.md).

```python
from trustrail.rules.output import (
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
from trustrail.rules.output import SycophancyRule

rule = SycophancyRule()
result = rule.evaluate(llm_output, context)
# Result is WARN — inspect finding.metadata["matched_phrase"] to surface to ops
```

Default action: `WARN`, severity `HIGH`.

Keep the model away from raw interpreter APIs. Prefer typed, narrowly scoped
tools that translate validated fields into operations. When dynamic execution
is unavoidable, use the [isolated execution boundary](code-execution-isolation.md).
