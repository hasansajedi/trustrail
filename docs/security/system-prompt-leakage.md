# System prompt leakage (OWASP LLM07:2025)

System prompts are model inputs, not secret stores or security boundaries. A
provider, compromised integration, prompt-injection attack, or model output may
expose their contents. Keep credentials, personal data, security configuration,
and authorization decisions outside the prompt even when leakage detection is
enabled.

trustrail provides controls at three points in the prompt lifecycle:

1. `SystemPromptValidator` admits only explicitly classified prompt variables,
   rejects sensitive values and authorization logic, and fails closed on invalid
   templates.
2. `SystemPromptExtractionRule` (`MT-002`) detects direct, partial,
   reconstruction, and encoded extraction requests at untrusted input
   boundaries. Structured prompt scanning also detects attacks split across
   sources.
3. `SystemPromptLeakageDetector` compares generated output with validated prompt
   references and blocks structured echoes, normalized verbatim fragments, and
   Base64-encoded fragments before delivery.

## Validate before provider submission

Use typed `{{name}}` placeholders and classify every interpolated value. The
default policy admits only `PUBLIC` and `BEHAVIOR`; it rejects personal data,
internal material, security configuration, authorization data, credentials,
and secrets.

```python
from trustrail import (
    SystemPromptDataClass,
    SystemPromptTemplate,
    SystemPromptValidator,
    SystemPromptVariable,
)

validated = SystemPromptValidator().require(
    SystemPromptTemplate(
        template_id="support-v1",
        template="You are a {{tone}} support assistant. Use reviewed public docs.",
        variables=(
            SystemPromptVariable(
                name="tone",
                value="concise",
                data_class=SystemPromptDataClass.BEHAVIOR,
            ),
        ),
    )
)

# Send validated.content as the system message only after validation succeeds.
```

The validator also runs trustrail's sensitive-data detectors over the template
and rendered result. This catches recognizable secrets even when a caller
misclassifies them as public. Rejections and exceptions retain only stable codes
and detector rule IDs; template text, variable values, and rendered content are
excluded from normal model serialization and representations.

Keep authenticated identity, tenant ownership, permissions, financial limits,
and allow/deny decisions in deterministic application code. A prompt may tell
the model to respect an application-provided decision, but it must not define
that decision.

## Check untrusted requests and generated output

Continue to scan every untrusted source with `Guard`, including tool responses,
retrieved documents, and memory. Use structured segments when multiple sources
are assembled into one request:

```python
safe_segments = Guard.default().protect_prompt_segments(segments)
```

After generation, compare the output with the exact prompt that was submitted:

```python
from trustrail import SystemPromptLeakageDetector, SystemPromptReference

reference = SystemPromptReference.from_validated(validated)
detector = SystemPromptLeakageDetector()
detector.require_safe(model_output, [reference])

# Only deliver model_output after require_safe() returns.
```

Prompt content is excluded from serialized `SystemPromptReference` objects and
content-free findings. Keep the reference in process only as long as required,
and do not place prompt objects in logs, traces, exception reporting, or audit
payloads.

## Policy tuning

`SystemPromptPolicy` controls admitted classifications, structural validation,
sensitive-data and authorization checks, and the rendered prompt size.
`SystemPromptLeakagePolicy` controls minimum fragment length, sliding word
windows, work bounds, and encoded/structured-echo detection. Reducing fragment
thresholds catches shorter disclosures but increases false positives. Outputs
or references larger than their configured scan bounds fail closed rather than
leaving an unscanned suffix.

Changing a forbidden classification to allowed is an explicit risk acceptance;
it does not make that content secret. Prefer removing the value from the prompt.

## Assumptions, limitations, and residual risk

- Data classifications and prompt references must come from trusted application
  code, not model output or untrusted request fields.
- Extraction rules are bounded pattern detectors. Novel wording, translation,
  semantic paraphrase, side channels, and multi-turn reconstruction may evade
  them; benign prompt-engineering discussions may also resemble attacks.
- Output comparison detects normalized exact fragments and decoded Base64
  fragments. It does not prove semantic non-disclosure or detect every encoding.
- Excluding content from Pydantic serialization and `repr` reduces accidental
  logging; the prompt remains present in process memory and at the model
  provider.
- Output blocking does not prevent exposure to provider logging, callbacks,
  traces, compromised dependencies, or observers earlier in the pipeline.
- Enforce provider retention settings, access control, tenant isolation, egress
  policy, monitoring, secret scanning, and credential rotation independently.
- If a secret was ever placed in a prompt, treat it as exposed and rotate it.
- Red-team the complete application across multiple turns and all input/output
  boundaries. Detection supplements data minimization and deterministic
  authorization; it does not replace them.
