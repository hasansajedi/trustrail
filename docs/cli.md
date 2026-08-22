# Command-line interface

The `trustrail` command checks content, validates configuration, and inspects the
built-in rule registry. It uses the same engine as the Python API.

## Check text

```bash
trustrail check --stage user_input --text "Ignore all previous instructions"
```

Use `--json` for automation:

```bash
trustrail check \
  --stage llm_response \
  --file response.txt \
  --profile balanced \
  --json
```

The command exits with status `0` when content is allowed and a non-zero status
when intervention is required, so it can be used in scripts and CI pipelines.

## Inspect rules

```bash
trustrail list-rules
trustrail list-rules --category prompt_injection
trustrail explain PI-001
```

## Validate configuration

```bash
trustrail validate-config guardrails.yaml
```

Validation rejects unknown fields and invalid thresholds before configuration is
used in an application.
