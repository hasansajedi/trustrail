# Migration and upgrades

aiRail follows semantic versioning, but guard decisions can change when rules
improve even if the public API remains compatible.

## Upgrade procedure

1. Pin the target version in a branch.
2. Read the project changelog and release notes.
3. Run unit and integration tests.
4. Replay your labeled benign and adversarial corpus.
5. Compare actions, scores, findings, and latency by rule ID.
6. Review newly blocked benign cases and newly allowed attack cases.
7. Deploy gradually and monitor decision-rate changes.

```bash
python -m pip install --upgrade "aiRail==<target-version>"
python -m pip check
pytest
```

When replacing another guardrail library, run both systems in parallel without
double-blocking. Normalize their outputs into a common evaluation report, define
the acceptance criteria for each boundary, then move enforcement one stage at a
time.
