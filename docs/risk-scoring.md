# Risk scoring

Each finding contributes to a bounded score from 0 to 100:

| Severity | Score contribution |
| --- | ---: |
| `CRITICAL` | Sets score to 100 |
| `HIGH` | 30 |
| `MEDIUM` | 15 |
| `LOW` | 5 |
| `INFO` | 0 |

Contributions accumulate and cap at 100. A critical finding always blocks. A
rule that explicitly returns `BLOCK` also blocks even when the aggregate score
is below `block_at`.

```python
from aiRail import GuardConfig

config = GuardConfig(block_at=60, warn_at=30)
```

The final action is evaluated in this order: critical finding, explicit rule
block, block threshold, warning threshold or explicit warning, then a remaining
high-severity warning. Otherwise the result is allowed.

Tune thresholds with labeled traffic representative of your application. Track
false positives and false negatives by rule ID, not score alone. Lower thresholds
for high-impact agent/tool boundaries and avoid changing production thresholds
without replay tests.
