# Add adaptive red-team gates

Run the repository gate locally with the same command used by GitHub Actions:

```bash
python -m aiRail.testing.red_team \
  tests/security_corpus/adaptive_prompt_injection.json
```

The JSON corpus contains labeled attack and benign seeds. Each seed selects
deterministic mutations such as alternating case, expanded whitespace,
punctuation wrapping, and zero-width interleaving. The gate scans every generated
variant at its configured `GuardStage`, then enforces minimum attack-detection and
maximum benign-blocking rates.

A failure report contains only stable case IDs, counts, and rates—not corpus text.
Use the ID to inspect the protected corpus locally. Add a new seed whenever a red
team exercise or production incident finds a bypass, and keep benign lookalikes
alongside attacks so a detection improvement cannot silently introduce excessive
blocking.

## Use a gate in application CI

```python
from aiRail.testing.red_team import PromptInjectionRegressionGate, RedTeamCorpus

corpus = RedTeamCorpus.from_path("security/adaptive-injection.json")
report = PromptInjectionRegressionGate().run(corpus)
report.assert_passed()
```

The default evaluator is `Guard.silent()`. Pass an object implementing
`check(value, stage)` to evaluate a custom aiRail configuration or an integration
adapter. Keep production-derived text in a restricted corpus; CI logs expose only
case identifiers, but repository access still exposes the JSON seeds.
