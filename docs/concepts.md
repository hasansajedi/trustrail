# Core Concepts

## Guard Stages

trustrail evaluates content at discrete stages in the LLM pipeline.

## Risk Scoring

- CRITICAL → score=100 (always block)
- HIGH → +30 per finding
- MEDIUM → +15 per finding
- LOW → +5 per finding

Default thresholds: block_at=80, warn_at=40.

## Fail Modes

- **CLOSED** (default): Block when a rule/provider fails
- **OPEN**: Allow with warning when a rule/provider fails
