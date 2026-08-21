# Command-line interface

The `aiRail` command checks content, validates configuration, and inspects the
built-in rule registry. It uses the same engine as the Python API.

## Check text

```bash
aiRail check --stage user_input --text "Ignore all previous instructions"
```

Use `--json` for automation:

```bash
aiRail check \
  --stage llm_response \
  --file response.txt \
  --profile balanced \
  --json
```

The command exits with status `0` when content is allowed and a non-zero status
when intervention is required, so it can be used in scripts and CI pipelines.

## Inspect rules

```bash
aiRail list-rules
aiRail list-rules --category prompt_injection
aiRail explain PI-001
```

## Validate configuration

```bash
aiRail validate-config guardrails.yaml
```

Validation rejects unknown fields and invalid thresholds before configuration is
used in an application.
