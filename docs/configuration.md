# Configuration

## Guard Profiles

```python
Guard.default()  # block_at=80, warn_at=40, fail_mode=CLOSED
Guard.balanced()  # block_at=60, warn_at=30, fail_mode=CLOSED
Guard.strict()  # block_at=40, warn_at=20, fail_mode=CLOSED
Guard.from_profile("paranoid")  # block_at=20, warn_at=5
Guard.from_profile("permissive")  # block_at=95, warn_at=70, fail_mode=OPEN
```

## GuardConfig

```python
from aiRail import GuardConfig, FailMode

config = GuardConfig(
    fail_mode=FailMode.CLOSED,
    block_at=70,
    warn_at=35,
    max_text_length=50_000,
    timeout_seconds=5.0,
    audit_enabled=True,
    strip_invisible_unicode=True,
    require_rag_context_labels=True,
    require_memory_write_approval=True,
)

guard = Guard(config=config)
```

## Risk Scoring

- CRITICAL finding → score = 100 (always block)
- HIGH finding → +30
- MEDIUM finding → +15
- LOW finding → +5
- INFO finding → +0

Default thresholds: block_at=80, warn_at=40.

## YAML Config

```yaml
fail_mode: closed
block_at: 70
warn_at: 35
max_text_length: 100000
audit_enabled: true
strip_invisible_unicode: true
require_rag_context_labels: true
require_memory_write_approval: true
```

`require_rag_context_labels` is enabled by default. It rejects plain joined text
at `GuardStage.RAG_CONTEXT`; use `Guard.build_rag_context()` and
`Guard.protect_rag_context()` to preserve document provenance and trust labels.

`require_memory_write_approval` is also enabled by default. Persistent writes
return `REQUIRE_APPROVAL` and must pass through `Guard.authorize_memory_write()`.
Disabling it leaves injection and sensitive-data scanning enabled, but removes the
human approval gate.

Validate with CLI:
```bash
aiRail validate-config guardrails.yaml
```
